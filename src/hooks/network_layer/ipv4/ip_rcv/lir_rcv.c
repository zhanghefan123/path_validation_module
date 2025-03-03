#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "structure/header/lir_header.h"
#include "structure/namespace/namespace.h"
#include "structure/crypto/bloom_filter.h"
#include <net/inet_ecn.h>
#include <linux/inetdevice.h>

int lir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    // 1. 初始化变量
    struct net* net = dev_net(dev);
    struct LiRHeader* lir_header = lir_hdr(skb);
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    int process_result;
    // 2. 进行消息的打印
    // PRINT_LIR_HEADER(lir_header);
    // 3. 进行初级的校验
    skb = lir_rcv_validate(skb, net);
    if (NULL == skb){
        LOG_WITH_PREFIX("validation failed");
        return 0;
    }
    // 4. 进行实际的转发
    process_result = lir_forward_packets(skb, pvs, net, orig_dev);
    // 5. 判断是否需要向上层提交或者释放
    if(NET_RX_SUCCESS == process_result) {
        // 为了进行实验, 暂时注释掉
        // LOG_WITH_PREFIX("local deliver");
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, lir_header->protocol,
                         receive_interface_address);
        return 0;
    } else {
        // 5.2 进行数据包的释放
        // LOG_WITH_PREFIX("drop packet");
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
        return 0;
    }
}

/**
 * 进行实际的数据包的转发
 * @param skb
 * @param pvh
 */
int lir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev){
    // 1. 初始化变量
    int index;
    int result = NET_RX_DROP; // 默认的情况是进行数据包的丢弃s
    struct ArrayBasedInterfaceTable* abit = pvs->abit;
    struct LiRHeader* pvh = lir_hdr(skb);
    unsigned char* previous_bf_bitset = pvs->bloom_filter->bitset;
    unsigned char* dest_pointer_start =  (unsigned char*)(pvh) + sizeof(struct LiRHeader);
    unsigned char* bloom_pointer_start = (unsigned char*)(pvh) + sizeof(struct LiRHeader) + pvh->dest_len;
    pvs->bloom_filter->bitset = bloom_pointer_start;

    // 2. 检查是否需要向上层进行提交
    for(index = 0; index < pvh->dest_len; index++){
        if(pvs->node_id == dest_pointer_start[index]){
            result = NET_RX_SUCCESS; // 应该向上层进行提交
            break;
        }
    }

    // 3. 遍历所有的接口进行转发
    for(index = 0; index < abit->number_of_interfaces; index++) {
        // 拿到链路标识
        int link_identifier = abit->interfaces[index]->link_identifier;
        // 检查是否在布隆过滤器之中
        if (0 == check_element_in_bloom_filter(pvs->bloom_filter, &(link_identifier), sizeof(link_identifier))) {
            // 如果入接口索引等于要转发的方向那么就不进行转发
            if(in_dev->ifindex != abit->interfaces[index]->interface->ifindex){
                struct sk_buff* copied_skb = skb_copy(skb, GFP_KERNEL);
                pv_packet_forward(copied_skb, abit->interfaces[index], current_ns);
            } else {
                LOG_WITH_PREFIX("not forward to incomming interface");
            }
        }
    }

    // 进行还原
    pvs->bloom_filter->bitset = previous_bf_bitset;
    return result;
}



struct sk_buff* lir_rcv_validate(struct sk_buff* skb, struct net* net){
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
    if (unlikely(ip_fast_csum((u8 *)pvh, pvh->hdr_len / 4)))
    {
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