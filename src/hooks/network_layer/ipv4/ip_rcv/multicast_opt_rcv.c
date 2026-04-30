#include <linux/inetdevice.h>
#include <net/inet_ecn.h>
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/namespace/namespace.h"
#include "structure/header/multicast_opt_header.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

int multicast_opt_rcv(struct sk_buff *skb, struct net_device *dev, struct net_device *orig_dev) {
    // 1. 进行变量的声明
    struct net *net = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    struct MulticastOptHeader *multicast_opt_header = multicast_opt_hdr(skb);
    int process_result;

    // 2. 进行初级的校验
    skb = multicast_opt_rcv_validate(skb, net);
    if (NULL == skb) {
        LOG_WITH_PREFIX("validation failed");
        kfree(skb);
        return 0;
    }
    // 3. 进行实际的转发
    process_result = multicast_opt_forward_packets(skb, pvs, net, orig_dev);

    // 4. 判断是否需要上层提交或者释放
    if (NET_RX_SUCCESS == process_result) {
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, multicast_opt_header->protocol, receive_interface_address);
    }
    return 0;
}

static bool destination_proof_verification(struct PathValidationStructure *pvs,
                                           struct SessionTableEntry *ste,
                                           struct OptOpv *opvs,
                                           unsigned char *pvf_start_pointer,
                                           time64_t *timestamp_pointer,
                                           unsigned char *static_fields_hash,
                                           struct shash_desc *hmac_api) {
    // 进行 opv combination 的构建
    unsigned char opv_combination[PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t)];
    memcpy(opv_combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(opv_combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
    memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH, &(ste->previous_node), sizeof(int));
    memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), timestamp_pointer, sizeof(time64_t));

    // 进行 opv_exp 的计算
    unsigned char *opv_expected = calculate_hmac(hmac_api,
                                                 opv_combination,
                                                 PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                 (unsigned char*)"sdk",
                                                 strlen("sdk"));
    // locate opv
    struct OptOpv *located_opv;
    located_opv = &opvs[pvs->node_id - 2];

    // 进行比较
    bool result = false;
    result = memory_compare(opv_expected, (unsigned char *) (located_opv), PVF_LENGTH);
    kfree(opv_expected);
    return result;
}


/**
 * 中间节点的验证和更新
 * @param ste 会话表项
 * @param static_fields_hash 静态字段的哈希
 * @param pvf_start_pointer pvf 起始指针
 * @return
 */
static bool intermediate_proof_verification_and_update(struct PathValidationStructure *pvs,
                                                       struct SessionTableEntry *ste,
                                                       unsigned char *static_fields_hash,
                                                       time64_t *timestamp_pointer,
                                                       struct OptOpv *opvs,
                                                       unsigned char *pvf_start_pointer,
                                                       struct shash_desc *hmac_api) {

    bool verification_result = false;

    // 进行 opv combination 的构建
    unsigned char opv_combination[PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t)];

    memcpy(opv_combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(opv_combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
    memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH, &(ste->previous_node), sizeof(int));
    memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), timestamp_pointer, sizeof(time64_t));

//    print_memory_in_hex(ste->session_key, HMAC_OUTPUT_LENGTH);
//    print_memory_in_hex(pvf_start_pointer, PVF_LENGTH);
//    print_memory_in_hex(static_fields_hash, HASH_LENGTH);
//    print_memory_in_hex((unsigned char*)(&ste->previous_node), sizeof(int));
//    print_memory_in_hex((unsigned char*)(timestamp_pointer), sizeof(time64_t));


    // 进行 opv_exp 的计算
    unsigned char *opv_expected = calculate_hmac(hmac_api,
                                                 opv_combination,
                                                 PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                 ste->session_key,
                                                 HMAC_OUTPUT_LENGTH);
    // locate opv
    struct OptOpv *located_opv;
    located_opv = &opvs[pvs->node_id - 2];

    // 进行比较
    verification_result = memory_compare(opv_expected, (unsigned char *) (located_opv), PVF_LENGTH);
    kfree(opv_expected);

    if(verification_result) {
        // 进行 pvf 字段的更新
        unsigned char* new_pvf = calculate_hmac(hmac_api,
                                                pvf_start_pointer,
                                                PVF_LENGTH,
                                                ste->session_key,
                                                HMAC_OUTPUT_LENGTH);

        // 进行 pvf 的更新
        memcpy(pvf_start_pointer, new_pvf, PVF_LENGTH);

        // 进行 pvf 的释放
        kfree(new_pvf);

//        printk(KERN_EMERG "node %d verification succeed\n", pvs->node_id);
    } else {
        printk(KERN_EMERG "node %d verification failed\n", pvs->node_id);
    }

    return verification_result;
}

int multicast_opt_forward_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                                  struct net_device *in_dev) {
    // 1. 初始化变量
    int final_result = NET_RX_DROP;
    struct MulticastOptHeader *multicast_opt_header = multicast_opt_hdr(skb);
    unsigned char *pvf_start_pointer = get_multicast_opt_pvf_start_pointer(multicast_opt_header);
    time64_t* timestamp_pointer = (time64_t *) get_multicast_opt_timestamp_start_pointer(multicast_opt_header);
    struct OptOpv *opvs = get_multicast_opt_opv_start_pointer(multicast_opt_header);
    struct SessionID *session_id = (struct SessionID *) (get_multicast_opt_session_id_start_pointer(
            multicast_opt_header));

    // 2. 进行 session_table_entry 查找
    struct SessionTableEntry *ste = find_ste_in_hbst(pvs->hbst, session_id);
    if (NULL == ste) {
        LOG_WITH_PREFIX("cannot find ste");
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // 3. 判断是否本地交付
    bool is_destination = ste->is_destination;

    // 4. 拿到 cpu ptr
    struct pv_struct *p = get_cpu_ptr(&validation_api);

    // 5. 进行 hash 值的计算
    unsigned char *static_fields_hash = calculate_multicast_opt_hash(p->hash_api, multicast_opt_header);

    // 6. 进行实际的处理转发
    if (is_destination) {
        // 校验结果
        bool result;
        // 进行校验
        result = destination_proof_verification(pvs, ste, opvs, pvf_start_pointer, timestamp_pointer,
                                                static_fields_hash, p->hmac_api);
        // 判断结果
        if (result) {
//            LOG_WITH_PREFIX("destination verification succeed");
            final_result = NET_RX_SUCCESS;
        } else {
            LOG_WITH_PREFIX("destination verification failed");
            final_result = NET_RX_DROP;
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
        }
    } else {
        // 校验结果
        bool result;
        // 进行校验和pvf的更新
        result = intermediate_proof_verification_and_update(pvs, ste,
                                                            static_fields_hash,
                                                            timestamp_pointer,
                                                            opvs,
                                                            pvf_start_pointer,
                                                            p->hmac_api);

        // 如果验证成功
        if (result) {
            // 进行重新的校验和的计算
            multicast_opt_send_check(multicast_opt_header);
            // 找到所有的接口进行转发
            int index;
            // 注意这里的 ites 是在会话建立的时候就明确了, 只有4项
            for (index = 0; index < ste->number_of_interfaces; index++) {
                struct InterfaceTableEntry *ite = ste->ites[index];
                struct sk_buff *copied_skb = skb_copy(skb, GFP_KERNEL);
                pv_packet_forward(copied_skb, ite, current_ns);
            }
            // 输出验证成功
//            printk(KERN_EMERG "validation succeed!\n");

            // 进行包的释放
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            // 设置丢包
            final_result = NET_RX_DROP;
        } else {
            // 进行包的释放
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            // 设置丢包
            final_result = NET_RX_DROP;
        }
    }

    // 7. 释放 cpu ptr
    put_cpu_ptr(p);

    return final_result;
}

struct sk_buff *multicast_opt_rcv_validate(struct sk_buff *skb, struct net *net) {
// 获取头部
    const struct MulticastOptHeader *multicast_opt_header;
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
    multicast_opt_header = multicast_opt_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (multicast_opt_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, multicast_opt_header->hdr_len))
        goto inhdr_error;

    multicast_opt_header = multicast_opt_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) multicast_opt_header, multicast_opt_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(multicast_opt_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (multicast_opt_header->hdr_len))
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

    multicast_opt_header = multicast_opt_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + multicast_opt_header->hdr_len;

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