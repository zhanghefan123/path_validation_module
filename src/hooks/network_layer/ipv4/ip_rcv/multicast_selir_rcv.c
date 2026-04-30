#include <net/inet_ecn.h>
#include <linux/inetdevice.h>
#include "structure/path_validation_structure.h"
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

/**
 * 多播路径验证数据包的接收
 * @param skb 数据包
 * @param dev she别
 * @param pt 数据包类型
 * @param orig_dev 入接口
 * @return
 */
int multicast_selir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    // 1. 进行变量的声明
    struct net *net = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
//    printk(KERN_EMERG "node %d receives packet\n", pvs->node_id);
    struct SELiRHeader *multicast_selir_header = selir_hdr(skb);
    int process_result;

    // 2. 进行初级的校验
    skb = multicast_selir_rcv_validate(skb, net);
    if (NULL == skb) {
        LOG_WITH_PREFIX("validation failed");
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // 3. 进行实际的转发
    process_result = multicast_selir_forward_packets(skb, pvs, net, orig_dev);

    // 4. 判断是否需要上层提交或者释放
    if (NET_RX_SUCCESS == process_result) {
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, multicast_selir_header->protocol, receive_interface_address);
    }
    return 0;
}

/**
 * 中间节点的验证和更新
 * @param ste 会话表项
 * @param pvs 路径验证数据结构
 * @param static_fields_hash 静态字段的哈希
 * @param pvf_start_pointer pvf 起始指针
 * @param ppf_start_pointer ppf 起始指针
 * @return
 */
static bool intermediate_proof_verification_and_update(struct SessionTableEntry *ste,
                                                       unsigned char *static_fields_hash,
                                                       unsigned char *pvf_start_pointer,
                                                       unsigned char *ppf_start_pointer,
                                                       struct shash_desc* hmac_api,
                                                       struct BloomFilter* bloom_filter) {
    // 1. 最终的判断结果
    bool verification_result = false;

    // 2. 进行布隆过滤器内部的数组的修改
    unsigned char *original_bit_set = bloom_filter->bitset;
    bloom_filter->bitset = ppf_start_pointer;

    // 3. 进行 pvf || hash 这个 combination 的计算
    unsigned char concatenation[PVF_LENGTH + HASH_LENGTH] = {0};
    memcpy(concatenation, pvf_start_pointer, PVF_LENGTH);
    memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_LENGTH);

    // 4. 进行 next_pvf 的计算, 并判断是否在 bf 之中
    unsigned char *next_pvf = calculate_hmac(hmac_api,
                                             concatenation,
                                             PVF_LENGTH + HASH_LENGTH,
                                             ste->session_key,
                                             HMAC_OUTPUT_LENGTH);

    // 5. 判断是否在布隆过滤器之中
    if (0 == check_element_in_bloom_filter(bloom_filter, next_pvf, PVF_LENGTH)) {
        verification_result = true;
    } else {
        verification_result = false;
    }

    // 6. 进行布隆过滤器内部数组的还原
    bloom_filter->bitset = original_bit_set;

    if(verification_result){
        // 7. 进行 pvf 的更新
        memcpy(pvf_start_pointer, next_pvf, PVF_LENGTH);
    }

    // 8. 进行 pvf 的释放
    kfree(next_pvf);

    // 9. 进行结果的返回
    return verification_result;
}

/**
 * 进行目的节点的校验
 * @param ste 会话表项
 * @param pvs 路径验证数据结构
 * @param static_fields_hash 静态字段哈希
 * @param pvf_start_pointer pvf 起始指针
 * @return
 */
static int destination_proof_verification(struct PathValidationStructure *pvs,
                                          struct EncPvf* encpvfs,
                                          unsigned char* pvf_start_pointer,
                                          unsigned char* static_fields_hash,
                                          struct shash_desc* hmac_api) {

    // 进行 concatenation的拼接
    unsigned char concatenation[PVF_LENGTH + HASH_LENGTH] = {0};
    memcpy(concatenation, pvf_start_pointer, PVF_LENGTH);
    memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_LENGTH);


    // 进行 hmac 的计算
    unsigned char* pvf_enc_expected = calculate_hmac(hmac_api,
                                                     concatenation,
                                                     PVF_LENGTH + HASH_LENGTH,
                                                     (unsigned char*)"sdk",
                                                     strlen("sdk"));

    // zhf 新增的代码 进行比较
    bool result = false;
    if(pvs->node_id == 5){
        result = memory_compare(pvf_enc_expected, (unsigned char*)(&encpvfs[0]), PVF_LENGTH);
    } else if(pvs->node_id == 7){
        result = memory_compare(pvf_enc_expected, (unsigned char*)(&encpvfs[1]), PVF_LENGTH);
    } else if(pvs->node_id == 9) {
        result = memory_compare(pvf_enc_expected, (unsigned char*)(&encpvfs[2]), PVF_LENGTH);
    } else if (pvs->node_id == 11){
        result = memory_compare(pvf_enc_expected, (unsigned char*)(&encpvfs[3]), PVF_LENGTH);
    }

    kfree(pvf_enc_expected);

    return result;
}

/**
 * 进行多播数据包的转发
 * @param skb
 * @param pvs
 * @param current_ns
 * @param in_dev
 * @return
 */
int multicast_selir_forward_packets(struct sk_buff *skb, struct PathValidationStructure *pvs,
                                    struct net *current_ns, struct net_device *in_dev) {
    // 1. 初始化变量
    int final_result = NET_RX_DROP;

    struct MulticastSelirHeader *multicast_selir_header = multicast_selir_hdr(skb);
    unsigned char *pvf_start_pointer = get_multicast_selir_pvf_start_pointer(multicast_selir_header);
    struct EncPvf* encpvfs = (struct EncPvf*)get_multicast_selir_enc_pvf_start_pointer(multicast_selir_header);
    unsigned char *ppf_start_pointer = get_multicast_selir_ppf_start_pointer(multicast_selir_header, multicast_selir_header->dest_len);
    struct SessionID *session_id = (struct SessionID *) (get_multicast_selir_session_id_start_pointer(multicast_selir_header));

    // 2. 进行 session_table_entry 的查找
    struct SessionTableEntry *ste = find_ste_in_hbst(pvs->hbst, session_id);
    if (NULL == ste) {
        LOG_WITH_PREFIX("cannot find ste");
        return NET_RX_DROP;
    }



    // 4. 判断是否需要进行本地的交付
    bool is_destination = ste->is_destination;

    // 5. 拿到 hash_api 以及 hmac_api
    // ---------------------------------------------------------------------------------------
    // struct pv_struct p = create_pv_struct(true, true, true, pvs->bloom_filter);
    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // ---------------------------------------------------------------------------------------


    // 3. 计算静态字段哈希
    unsigned char *static_fields_hash = calculate_multicast_selir_hash(p->hash_api, multicast_selir_header);

    if (is_destination) { // 5. 如果是目的节点的话
        // 校验结果
        bool result;
        // 进行校验
        result = destination_proof_verification(pvs, encpvfs, pvf_start_pointer, static_fields_hash, p->hmac_api);
        // 判断结果
        if(result){
//            printk(KERN_EMERG "destination verification succeed");
            final_result = NET_RX_SUCCESS;
        } else {
//            LOG_WITH_PREFIX("destination verification failed");
            final_result = NET_RX_DROP;
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
        }
    } else { // 6. 如果是中间节点的话
        // 校验结果
        bool result;
        // 进行校验和pvf的更新
        result = intermediate_proof_verification_and_update(ste,
                                                            static_fields_hash,
                                                            pvf_start_pointer,
                                                            ppf_start_pointer,
                                                            p->hmac_api,
                                                            p->bloom_filter);

        // 如果验证成功
        if (result) {
            // 进行重新的校验和的计算
            multicast_selir_send_check(multicast_selir_header);
            // 找到所有的接口进行转发
            int index;
            for(index = 0; index < ste->number_of_interfaces; index++){
                struct InterfaceTableEntry* ite = ste->ites[index];
                struct sk_buff* copied_skb = skb_copy(skb, GFP_KERNEL);
                pv_packet_forward(copied_skb, ite, current_ns);
            }
//            LOG_WITH_PREFIX("intermediate validation succeed!");
            // 进行自己的释放
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            final_result =  NET_RX_DROP;
        } else { // 如果验证失败
            LOG_WITH_PREFIX("intermediate validation failed!");
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            final_result =  NET_RX_DROP;
        }
    }

    // 进行哈希的释放
    kfree(static_fields_hash);

//    free_pv_struct(&p);
    put_cpu_ptr(p);


    return final_result;
}

struct sk_buff *multicast_selir_rcv_validate(struct sk_buff *skb, struct net *net) {
// 获取头部
    const struct SELiRHeader *multicast_selir_header;
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
    multicast_selir_header = selir_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (multicast_selir_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, multicast_selir_header->hdr_len))
        goto inhdr_error;

    multicast_selir_header = selir_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) multicast_selir_header, multicast_selir_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(multicast_selir_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (multicast_selir_header->hdr_len))
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

    multicast_selir_header = selir_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + multicast_selir_header->hdr_len;

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