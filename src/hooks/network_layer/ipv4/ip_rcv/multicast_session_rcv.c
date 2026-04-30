#include <net/inet_ecn.h>
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/namespace/namespace.h"
#include "structure/header/multicast_session_header.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"


int multicast_session_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
                          struct net_device *orig_dev) {
    struct net *current_ns = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 1. 初始化变量
    int process_result;
    // 2. 进行初级的校验
    skb = multicast_session_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    process_result = forward_multicast_session_setup_packets(skb, pvs, current_ns, orig_dev);

    // 5. 进行数据包本地的处理 -> session packet 本就不需要进行本地交付
    if (NET_RX_DROP == process_result) {
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    }
    return 0;
}

static bool judge_is_destination(const int *destinations, int destination_count, int current_node_id) {
    int index;
    bool arrived_destination = false;
    // 遍历所有的节点看自己是否是目的节点之中的一个
    for (index = 0; index < destination_count; index++) {
        if (current_node_id == destinations[index]) {
            arrived_destination = true;
            break;
        }
    }
    return arrived_destination;
}

/**
 * 中间节点进行会话数据包的处理
 */
static void intermediate_process_packets(struct MulticastSessionHeader *multicast_session_header,
                                         struct PathValidationStructure *pvs, struct sk_buff *skb,
                                         struct net *current_ns, struct SessionID* session_id, struct net_device* orig_dev) {
    // 0. 索引
    int index;
    // 1. 拿到目的节点的数量
    int destination_count = multicast_session_header->destination_count;
    // 3. 拿到链路标识的数量
    int link_identifiers_count = multicast_session_header->link_identifiers_count;
    // 4. 进行路径的打印
    int *actual_path = (int *) get_multicast_session_setup_actual_path_pointer(multicast_session_header,
                                                                               link_identifiers_count,
                                                                               destination_count);
    // 4. 拿到所有的链路标识
    int *link_identifiers = (int *) get_multicast_session_setup_link_identifiers_pointer(multicast_session_header);

    // 5. 根据数据包所存储的 link_identifiers 进行查找
    int inner_index;
    int interface_index = 0;

    struct InterfaceTableEntry* output_interfaces[4];
//    struct InterfaceTableEntry** output_interfaces = (struct InterfaceTableEntry**)(kmalloc(sizeof(struct InterfaceTableEntry*) * 4, GFP_KERNEL));
    output_interfaces[0] = NULL;
    output_interfaces[1] = NULL;
    output_interfaces[2] = NULL;
    output_interfaces[3] = NULL;
    for (index = 0; index < pvs->abit->number_of_interfaces; index++) {
        struct InterfaceTableEntry *ite_tmp = pvs->abit->interfaces[index];
        if(ite_tmp->interface->ifindex == orig_dev->ifindex){
            continue;
        }
        bool forward = false;
        for (inner_index = 0; inner_index < link_identifiers_count; inner_index++) {
            if (ite_tmp->link_identifier == link_identifiers[inner_index]) {
                forward = true;
                break;
            }
        }
        if (forward) {
            output_interfaces[interface_index++] = ite_tmp;
        }
    }
    // 进行实际路径的设置, 节点的记录
    actual_path[multicast_session_header->current_path_index] = pvs->node_id;


    // 5. 创建会话表项
    char secret_value[20];
    snprintf(secret_value, sizeof(secret_value), "key-%d", pvs->node_id);
    unsigned char* session_key = calculate_hmac(pvs->hmac_api,
                                                (unsigned char*)(session_id),
                                                sizeof(struct SessionID),
                                                (unsigned char*)(secret_value),
                                                (int)(strlen(secret_value)));

    // 6. 创建堆上的 output_interfaces
    struct InterfaceTableEntry** output_interfaces_at_heap = (struct InterfaceTableEntry**)(kmalloc(sizeof(struct InterfaceTableEntry*) * interface_index, GFP_KERNEL));

    // 7. 初始化对上的 output_interfaces
    for(index = 0; index < interface_index; index++){
        output_interfaces_at_heap[index] = output_interfaces[index];
    }

    // 记录前驱的节点是什么
    // --------------------------------------------------------------------------
    int previous_node_id = -1;
    for(index = 0; index < pvs->abit->number_of_interfaces; index++){
        if(orig_dev->ifindex == pvs->abit->interfaces[index]->interface->ifindex){
            previous_node_id = pvs->abit->interfaces[index]->target_node_id;
            break;
        }
    }
    // --------------------------------------------------------------------------

    struct SessionTableEntry* ste = init_ste_in_intermediate_for_multicast(session_id, output_interfaces_at_heap, interface_index, session_key, previous_node_id);

    // 更新到 session_table_entry 之中
    ste->current_hop = multicast_session_header->current_path_index;

    // 将当前的路径索引进行更新 (注意只有 ste->current_hop 中更新了, 才能更新)
    multicast_session_header->current_path_index += 1;

    // send check (一定要在所有的字段更新完后计算校验和)
    multicast_session_setup_send_check(multicast_session_header);

    // 6. 添加会话表项
    add_entry_to_hbst(pvs->hbst, ste);

    // 7. 进行接口表的遍历, 并且进行数据包的转发
    for (index = 0; index < interface_index; index++) {
        if (NULL != output_interfaces_at_heap[index]) {
            struct sk_buff *skb_cp = skb_copy(skb, GFP_KERNEL);
            pv_packet_forward(skb_cp, output_interfaces_at_heap[index], current_ns);
        } else {
            break;
        }
    }
}

/**
 * 目的节点进行会话数据包的处理
 */
static void destination_process_packets(struct MulticastSessionHeader *multicast_session_header,
                                        struct PathValidationStructure *pvs,
                                        struct SessionID *session_id,
                                        struct net_device* orig_dev) {
    // 索引
    int index;
    // 实际路径的长度
    int actual_path_length = multicast_session_header->current_path_index;
    // 总的链路标识的数量
    int link_identifiers_count = multicast_session_header->link_identifiers_count;
    // 总的目的节点的数量
    int destinations_count = multicast_session_header->destination_count;
    // 实际的路径
    int *actual_path = (int *) (get_multicast_session_setup_actual_path_pointer(multicast_session_header,
                                                                                link_identifiers_count,
                                                                                destinations_count));
    // 进行 session_key 的计算
    char secret_value[20];
    snprintf(secret_value, sizeof(secret_value), "sdk");
    unsigned char *session_key = calculate_hmac(pvs->hmac_api,
                                                (unsigned char *) (session_id),
                                                sizeof(struct SessionID),
                                                (unsigned char *) (secret_value),
                                                (int) (strlen(secret_value)));

    // 记录前驱的节点是什么
    // --------------------------------------------------------------------------
    int previous_node_id = -1;
    for(index = 0; index < pvs->abit->number_of_interfaces; index++){
        if(orig_dev->ifindex == pvs->abit->interfaces[index]->interface->ifindex){
            previous_node_id = pvs->abit->interfaces[index]->target_node_id;
            break;
        }
    }
    // --------------------------------------------------------------------------


    // 创建会话表项
    struct SessionTableEntry *ste = init_ste_in_dest_for_multicast(session_id,
                                                                   actual_path_length,
                                                                   actual_path_length,
                                                                   session_key,
                                                                   previous_node_id);

    // 进行每个节点的 session_key 的提前生成
    for (index = 0; index < actual_path_length; index++) {
        // 拿到中间节点 id
        int node = actual_path[index];
        // 拿到 secret value
        snprintf(secret_value, sizeof(secret_value), "key-%d", node);
        // 计算 session_key
        unsigned char* session_key_tmp = calculate_hmac(pvs->hmac_api,
                                                        (unsigned char*) session_id,
                                                        sizeof(struct SessionID),
                                                        (unsigned char*)(secret_value),
                                                        (int)(strlen(secret_value)));
        // 在 session_keys 之中进行存储
        ste->session_keys[index] = session_key_tmp;
    }

    add_entry_to_hbst(pvs->hbst, ste);
}

int forward_multicast_session_setup_packets(struct sk_buff *skb, struct PathValidationStructure *pvs,
                                            struct net *current_ns, struct net_device* orig_dev) {

    // 1. 拿到首部
    struct MulticastSessionHeader *multicast_session_header = multicast_session_hdr(skb);
    // 2. 判断是否到达了目的节点
    int destination_count = multicast_session_header->destination_count;
    int *destinations = (int *) get_multicast_session_setup_destination_pointer(multicast_session_header,
                                                                                multicast_session_header->link_identifiers_count);
    bool arrived_destination = judge_is_destination(destinations, destination_count, pvs->node_id);
    // 3. 拿到 session_id
    struct SessionID *session_id = (struct SessionID *) (get_multicast_session_setup_session_id_pointer(
            multicast_session_header));
    // 4. 目的地的处理方式
    if (arrived_destination) {
//        printk(KERN_EMERG "destination %d receive session setup packets\n", pvs->node_id);
        destination_process_packets(multicast_session_header, pvs, session_id, orig_dev);
    } else { // 5. 非目的地的处理方式
//        printk(KERN_EMERG "node %d forward session setup packets\n", pvs->node_id);
        intermediate_process_packets(multicast_session_header, pvs, skb, current_ns, session_id, orig_dev);
    }
    return NET_RX_DROP;
}

struct sk_buff *multicast_session_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct MulticastSessionHeader *multicast_session_header;
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
    multicast_session_header = multicast_session_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (multicast_session_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, multicast_session_header->hdr_len))
        goto inhdr_error;

    multicast_session_header = multicast_session_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) multicast_session_header, multicast_session_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(multicast_session_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (multicast_session_header->hdr_len))
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

    multicast_session_header = multicast_session_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + multicast_session_header->hdr_len;

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
