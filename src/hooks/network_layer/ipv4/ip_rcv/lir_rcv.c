#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/header/lir_header.h"
#include "structure/namespace/namespace.h"
#include "structure/crypto/bloom_filter.h"
#include <net/inet_ecn.h>
#include <linux/inetdevice.h>

int lir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    // 1. 初始化变量
    u64 start_time = ktime_get_real_ns();
    struct net *net = dev_net(dev);
    struct LiRHeader *lir_header = lir_hdr(skb);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    int process_result;
    int current_hop = lir_header->current_hop;
    // 2. 进行消息的打印
    // PRINT_LIR_HEADER(lir_header);
    // 3. 进行初级的校验
    skb = lir_rcv_validate(skb, net);
    if (NULL == skb) {
        LOG_WITH_PREFIX("validation failed");
        return 0;
    }
    // 4. 进行实际的转发
    process_result = lir_forward_packets(skb, pvs, net, orig_dev);

    // 5. 进行转发的打印
    // print_lir_forwarding_time_consumption(current_hop, pvs, start_time);

    // 6. 判断是否需要向上层提交或者释放
    if (NET_RX_SUCCESS == process_result) {
        // 6.1 进行本地的接收
        // 为了进行实验, 暂时注释掉
        // LOG_WITH_PREFIX("local deliver");
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, lir_header->protocol,
                         receive_interface_address);
        return 0;
    } else if (NET_RX_DROP == process_result) {
        // 6.2 进行数据包的释放
        // LOG_WITH_PREFIX("drop packet");
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
        return 0;
    } else {
        // 6.3 不进行任何的操作 (说明原始数据包被转发走了)
        return 0;
    }
}

/**
 * attac
 * 打印 lir 转发的时间消耗 (包括单次封装节点和多次封装节点的)
 * @param current_hop
 */
void print_lir_forwarding_time_consumption(int current_hop, struct PathValidationStructure *pvs, u64 start_time) {
    if (0 == current_hop) {
        printk(KERN_EMERG "node %d, lir forwarding takes %llu ns to forward packet\n", pvs->node_id,
               ktime_get_real_ns() - start_time);
    }
    if ((pvs->lir_single_time_encoding_count - 1) == current_hop) {
        printk(KERN_EMERG "node %d, lir reencoding takes %llu ns to forward packet\n", pvs->node_id,
               ktime_get_real_ns() - start_time);
    }
}


/**
 * 进行实际的数据包的转发
 * @param skb
 * @param pvh
 */
int lir_forward_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                        struct net_device *in_dev) {
    // 1. 初始化变量
    int index;
    int result = NET_RX_DROP; // 默认的情况是进行数据包的丢弃s
    struct ArrayBasedInterfaceTable *abit = pvs->abit;
    struct LiRHeader *pvh = lir_hdr(skb);
    unsigned char *previous_bf_bitset = pvs->bloom_filter->bitset;
    unsigned char *dest_pointer_start = (unsigned char *) (pvh) + sizeof(struct LiRHeader);
    unsigned char *bloom_pointer_start = (unsigned char *) (pvh) + sizeof(struct LiRHeader) + pvh->dest_len;
    bool packet_forwarded = false;
    int first_destination = *((unsigned char *) dest_pointer_start);
    pvs->bloom_filter->bitset = bloom_pointer_start; // 进行 bf 的设置

    // 2. 检查是否需要向上层进行提交
    for (index = 0; index < pvh->dest_len; index++) {
        if (pvs->node_id == dest_pointer_start[index]) {
            result = NET_RX_SUCCESS; // 应该向上层进行提交
            break;
        }
    }

    // 3. 进行 current_hop 的更新 --> current_hop 的作用是方便节点识别出当前是否应该进行打印
    pvh->current_hop += 1;
    lir_send_check(pvh);

    // 4. 拿到所有应该转发的接口
    int forward_interface_count = 0;
    struct InterfaceTableEntry *forward_interfaces[4] = {NULL, NULL, NULL, NULL};
    for (index = 0; index < abit->number_of_interfaces; index++) {
        // 拿到链路标识
        int link_identifier = abit->interfaces[index]->link_identifier;
        // 检查是否在布隆过滤器之中
        if (0 == check_element_in_bloom_filter(pvs->bloom_filter, &(link_identifier), sizeof(link_identifier))) {
            forward_interfaces[forward_interface_count++] = abit->interfaces[index];
        }
    }

    // 5. 进行转发, 前面的接口
    for (index = 0; index < forward_interface_count; index++) {
        if (index == forward_interface_count - 1) { // 如果 index == forward_interface_count - 1 说明是最后一个接口
            // 将收到的数据包转发出去就可以了
            pv_packet_forward(skb, forward_interfaces[index], current_ns);
        } else { // 如果 index == forward_interface_count - 1 说明不是最后一个接口
            // 拷贝数据包并进行转发
            struct sk_buff* copied_skb = skb_copy(skb, GFP_KERNEL);
            pv_packet_forward(copied_skb, forward_interfaces[index], current_ns);
        }
    }

    // 6. 如果转发的接口数量大于0, 那么应该将转发了数据包设置为 true, 并且上层不用进行任何处理
    if(forward_interface_count > 0) {
        packet_forwarded = true;
        result = NET_RX_NOTHING;
    }

    // 7. 判断是否没有转发, 并且不是最终的目的节点, 说明是中间节点
    if (!packet_forwarded && (NET_RX_SUCCESS != result)) {
        // 如果数据包没有转发, 说明这个是中间节点, 进行路由表的查找
        struct RoutingTableEntry *rte = find_sre_in_hbrt(pvs->hbrt, pvs->node_id, first_destination);
        if (NULL != rte) {
            // 进行布隆过滤器的重置并将新的链路标识进行嵌入
            reset_bloom_filter(pvs->bloom_filter);

            // 将链路标识放到布隆过滤器之中
            for (index = 0; (index < rte->path_length) && (index < pvs->lir_single_time_encoding_count); index++) {
                int link_identifier = rte->link_identifiers[index];
                push_element_into_bloom_filter(pvs->bloom_filter, &(link_identifier), sizeof(link_identifier));
            }

            // 进行重新的校验和的计算
            lir_send_check(pvh);

            // 将数据包从 rte 所指定的出接口转发出去
            pv_packet_forward(skb, rte->output_interface, current_ns);
        }
    }

    // 进行还原
    pvs->bloom_filter->bitset = previous_bf_bitset; // 进行 bf 的还原
    return result;
}


struct sk_buff *lir_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct LiRHeader *pvh;
    // 丢包的原因
    int drop_reason;
    // 总的长度
    u32 len;

    // 进行 pkt_type 的设置 (由于设置的是 BROADCAST_MAC 所以这里不行)
    // 1. PACKET_HOST 代表目的地是本机
    // 2. PACKET_OTHERHOST 代表目的地是其他主机
    skb->pkt_type = PACKET_HOST;

    /* When the interface is in promisc. mode, drop all the crap
     * that it receives, do not try to analyse it
     * 如果是其他主机，那么直接丢
     */
    if (skb->pkt_type == PACKET_OTHERHOST) {
        dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
        drop_reason = SKB_DROP_REASON_OTHERHOST;
        goto drop;
    }

    __IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto out;
    }

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

    // 确保存在足够的空间
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        goto inhdr_error;

    // 解析网络层首部
    pvh = lir_hdr(skb);

    /*
     *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
     *
     *	Is the datagram acceptable?
     *
     *	1.	Length at least the size of an ip header
     *	2.	Version of 4
     *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
     *	4.	Doesn't have a bogus length
     */

    BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
    BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
    BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
    __IP_ADD_STATS(net,
                   IPSTATS_MIB_NOECTPKTS + (pvh->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, pvh->hdr_len))
        goto inhdr_error;

    pvh = lir_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) pvh, pvh->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(pvh->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (pvh->hdr_len))
        goto inhdr_error;
    // --------------------------------------------------------

    /* Our transport medium may have padded the buffer out. Now we know it
     * is IP we can trim to the true length of the frame.
     * Note this now means skb->len holds ntohs(iph->tot_len).
     */
    if (pskb_trim_rcsum(skb, len)) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto drop;
    }

    pvh = lir_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + pvh->hdr_len;

    /* Remove any debris in the socket control block */
    memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    IPCB(skb)->iif = skb->skb_iif;

    /* Must drop socket now because of tproxy. */
    if (!skb_sk_is_prefetched(skb))
        skb_orphan(skb);

    return skb;

    csum_error:
    drop_reason = SKB_DROP_REASON_IP_CSUM;
    __IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
    inhdr_error:
    if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
        drop_reason = SKB_DROP_REASON_IP_INHDR;
    __IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
    drop:
    kfree_skb_reason(skb, drop_reason);
    out:
    return NULL;
}