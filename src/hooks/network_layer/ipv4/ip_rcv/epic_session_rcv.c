#include <net/inet_ecn.h>
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/namespace/namespace.h"
#include "structure/routing/table_common.h"
#include "structure/header/epic_session_header.h"
#include "structure/header/epic_fields_length.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

int epic_session_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    struct net *current_ns = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 1. 初始化变量
    int process_result;
    // 2. 进行初级的校验
    skb = epic_session_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    // 3. 根据包头内携带的信息进行转发
    process_result = forward_epic_session_setup_packets(skb, pvs, current_ns, orig_dev);

    // 4. 进行数据包本地的处理 -> session packet 本就不需要进行本地交付
    if (NET_RX_DROP == process_result) {
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    }
    return 0;
}

// 目的节点进行接收
static void destination_process_epic_session_packets(struct PathValidationStructure *pvs, struct EpicSessionHeader *epic_session_header, struct net_device* orig_dev) {
    // 1. 进行表项的初始化 source 和 dest 需要是相反的
    int source = epic_session_header->dest;
    int destination = epic_session_header->source;
    // 2. 拿到 path_time_stamp
    unsigned char* timestamp_pointer = get_epic_session_setup_timestamp_pointer(epic_session_header);
    u64 path_timestamp = *((u64*)(timestamp_pointer));
    printk(KERN_EMERG "destination received timestamp: %llu", path_timestamp);
    // 3. 拿到 HopIdentifiers
    struct EpicHopIdentifier* hop_identifiers = get_epic_session_setup_hop_identifiers_start_pointer(epic_session_header);
    // 4. 拿到 HopAuthenticators
    struct EpicHopAuthenticator* hop_authenticators = (struct EpicHopAuthenticator*) get_epic_session_setup_hop_authenticator_start_pointer(epic_session_header);
    // 5. 这里如何将  hop_identifiers 以及 hop_authenticators 进行逆序
    // -----------------------------------------------------------------------------------
    int index;
    int epic_session_hops = epic_session_header->length_of_path - 1;
    // 大于1 才需要进行逆序
    if(epic_session_hops > 1) {
        // 进行 hop_identifiers 的逆序
        for(index = 0; index < epic_session_hops / 2; index++){
            // 交换结构体内容而不是指针
            struct EpicHopIdentifier temp = hop_identifiers[index];
            hop_identifiers[index] = hop_identifiers[epic_session_hops - 1 - index];
            hop_identifiers[epic_session_hops - 1 - index] = temp;
        }
        // 进行 hop_authenticators 的逆序
        for (index = 0; index < epic_session_hops / 2; index++) {
            // 交换结构体内容而不是指针
            struct EpicHopAuthenticator temp = hop_authenticators[index];
            hop_authenticators[index] = hop_authenticators[epic_session_hops - 1 - index];
            hop_authenticators[epic_session_hops - 1 - index] = temp;
        }
    }

    // 交换了以后进行跳的打印
    LOG_WITH_EDGE("destination received hop identifiers");
    for(index = 0; index < epic_session_hops; index++){
        PRINT_EPIC_HOP_IDENTIFIER(&(hop_identifiers[index]));
    }
    LOG_WITH_EDGE("destination received hop identifiers");

    // 交换了以后进行 hop authenticator 的打印
    LOG_WITH_EDGE("destination received hop authenticators");
    for(index = 0; index < epic_session_hops; index++){
        print_memory_in_hex((unsigned char*)&(hop_authenticators[index]), HOP_AUTHENTICATOR_LENGTH);
    }
    LOG_WITH_EDGE("destination received hop authenticators");

    // HI1 --> HI2
    // sigma1 --> sigma2
    // (TSpath || HI1 || ZERO) (TSPATH || HI2 || sigma1[truncate])
    // -----------------------------------------------------------------------------------

    // 6. 根据 orig_dev 可以找到对应的 interface_table_entry
    struct InterfaceTableEntry* incoming_interface_table_entry = NULL;
    for(index = 0; index < pvs->abit->number_of_interfaces; index++){
        struct InterfaceTableEntry* ite_tmp = pvs->abit->interfaces[index];
        if(ite_tmp->interface->ifindex == orig_dev->ifindex){
            incoming_interface_table_entry = ite_tmp;
            break;
        }
    }
    if (NULL == incoming_interface_table_entry){
        return;
    }

    // 7. 初始化表项
    struct EpicSessionTableEntry* este = init_este(source, destination, path_timestamp, hop_identifiers,
            hop_authenticators, epic_session_header->length_of_path, incoming_interface_table_entry);

    // 8. 将表项添加到表之中
    int result = add_entry_to_hbest(pvs->hbest, este);
    if (ADD_SUCCESS == result){
        printk(KERN_EMERG "add entry to hbest success\n");
    } else if (CANNOT_FIND_BUCKET == result) {
        printk(KERN_EMERG "cannot find bucket\n");
    } else {
        printk(KERN_EMERG "already exists\n");
    }
}

// 中间节点处理 session_packets
static void intermediate_process_epic_session_packets(struct sk_buff *skb,
                                                      struct PathValidationStructure *pvs,
                                                      struct EpicSessionHeader *epic_session_header,
                                                      struct net *current_ns,
                                                      struct net_device* orig_dev,
                                                      int current_path_index) {


    // 1. 获取 hop_identifiers 存储的位置
    struct EpicHopIdentifier *hop_identifiers = get_epic_session_setup_hop_identifiers_start_pointer(epic_session_header);

    // 2. 获取当前的出链路标识
    int current_link_identifier = hop_identifiers[current_path_index].link_id;

    // 3. 寻找入接口对应的链路标识
    int incoming_link_identifier = -1;
    int index;
    for(index = 0; index < pvs->abit->number_of_interfaces; index++){
        struct InterfaceTableEntry* ite_tmp = pvs->abit->interfaces[index];
        if(ite_tmp->interface->ifindex == orig_dev->ifindex){
            incoming_link_identifier = ite_tmp->link_identifier;
            break;
        }
    }
    if(incoming_link_identifier == -1){
        return;
    }

    // 4. 更新入接口标识
    hop_identifiers[current_path_index].incoming_link_id = incoming_link_identifier;

    // 5. 寻找出接口
    struct InterfaceTableEntry *ite = NULL;
    for (index = 0; index < pvs->abit->number_of_interfaces; index++) {
        struct InterfaceTableEntry *ite_tmp = pvs->abit->interfaces[index];
        if (current_link_identifier == ite_tmp->link_identifier) {
            ite = ite_tmp;
            break;
        }
    }
    // 如果找不到直接返回
    if(NULL == ite){
        return;
    }



    // 6. 进行拼接的构建 - 准备进行 hop authenticator 的计算
    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    unsigned char concatenation[PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH + SEGMENT_IDENTIFIER_LENGTH] = {0};  // 这里使用的是全长的 hash 而不是截断的 hash

    // 6.1 获取 timestamp 存储的位置
    unsigned char* timestamp_pointer = get_epic_session_setup_timestamp_pointer(epic_session_header);

    // 6.2 获取 hop authenticator 存储的位置
    struct EpicHopAuthenticator* hop_authenticators = (struct EpicHopAuthenticator*)get_epic_session_setup_hop_authenticator_start_pointer(epic_session_header);

    // 6.3 构建拼接
    // 6.3.1 拼接 timestamp
    memcpy(concatenation, timestamp_pointer, PATH_TIMESTAMP_LENGTH);
    // 6.3.2 拼接 hop_identifiers
    memcpy(concatenation + PATH_TIMESTAMP_LENGTH, &hop_identifiers[current_path_index], HOP_IDENTIFIER_LENGTH);
    // 6.3.3 拼接
    if(current_path_index != 0){
        memcpy(concatenation + PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH, &(hop_authenticators[current_path_index-1]), SEGMENT_IDENTIFIER_LENGTH);
    }
    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------

    // 7. 根据拼接进行 hop authenticator 的计算以及放置
    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // 进行 hash_api 和 hmac_api 的获取
    struct pv_struct* p = get_cpu_ptr(&validation_api);

    // 进行 as-level key 的配置
    char as_level_key[20];
    snprintf(as_level_key, sizeof(as_level_key), "key-%d", pvs->node_id);
    unsigned char* hop_authenticator = calculate_hmac(p->hmac_api,
                                                      concatenation,
                                                      PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH + SEGMENT_IDENTIFIER_LENGTH,
                                                      (unsigned char*)(as_level_key),
                                                      (int)(strlen(as_level_key)));

    put_cpu_ptr(p);

    // 进行计算出来的 hop_authenticator 的打印
    LOG_WITH_EDGE("intermediate router calculated hop authenticator");
    print_memory_in_hex(concatenation, PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH + SEGMENT_IDENTIFIER_LENGTH);
    print_memory_in_hex(hop_authenticator, HOP_AUTHENTICATOR_LENGTH);
    LOG_WITH_EDGE("intermediate router calculated hop authenticator");
    memcpy((unsigned char*)(&(hop_authenticators[current_path_index])), hop_authenticator, HOP_AUTHENTICATOR_LENGTH);
    kfree(hop_authenticator);
    // -------------------------------------------------------------------------------------------------------------------------------------------------------------------

    // 7. 进行 +1 的操作
    epic_session_header->current_path_index += 1;

    // 8. 在完成更新之后进行 check 校验和的更新
    epic_session_setup_send_check(epic_session_header);

    // 9. 进行数据包的转发
    if (NULL != ite->interface) {
        pv_packet_forward(skb, ite, current_ns);
    }
}

// 对中间节点和目的节点进行不同处理
int forward_epic_session_setup_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns, struct net_device* orig_dev) {
    // 1. 拿到首部
    struct EpicSessionHeader *epic_session_header = epic_session_hdr(skb);
    // 2. 拿到当前的索引
    int current_index = epic_session_header->current_path_index;
    // 3. 目的节点
    int destination = epic_session_header->dest;
    // 4. 拿到当前的 id
    int current_node_id = pvs->node_id;
    if (current_node_id == destination) {
        LOG_WITH_PREFIX("Destination receives epic session setup packet");
        destination_process_epic_session_packets(pvs, epic_session_header, orig_dev);
        return NET_RX_DROP;
    } else {
        LOG_WITH_PREFIX("On-path Router receives epic session setup packet");
        intermediate_process_epic_session_packets(skb, pvs, epic_session_header, current_ns, orig_dev, current_index);
        return NET_RX_NOTHING;
    }
}

// 基础校验流程
struct sk_buff *epic_session_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct EpicSessionHeader *epic_session_header;
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
    epic_session_header = epic_session_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (epic_session_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, epic_session_header->hdr_len))
        goto inhdr_error;

    epic_session_header = epic_session_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) epic_session_header, epic_session_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(epic_session_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (epic_session_header->hdr_len))
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

    epic_session_header = epic_session_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + epic_session_header->hdr_len;

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