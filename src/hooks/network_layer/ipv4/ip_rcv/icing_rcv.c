#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/header/icing_header.h"
#include "structure/namespace/namespace.h"
#include "structure/crypto/crypto_structure.h"
#include <net/inet_ecn.h>
#include <linux/inetdevice.h>
#include <net/sch_generic.h>

int icing_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed) {
    // 1. 初始化变量
    struct net *net = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    struct ICINGHeader *icing_header = icing_hdr(skb);
    int process_result;
    // 2. 进行初级的校验
    skb = icing_rcv_validate(skb, net);
    if (NULL == skb){
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    // 3. 进行实际的转发
    process_result = icing_forward_packets(skb, pvs, net, orig_dev, intermediate_verification_time_elapsed, destination_verification_time_elapsed);
    // 4. 判断是进行本地交付还是直接丢弃
    if (NET_RX_SUCCESS == process_result) {
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, icing_header->protocol,
                         receive_interface_address);
    }
    return 0;
}

struct sk_buff *icing_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct ICINGHeader *icing_header;
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
    icing_header = icing_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (icing_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, icing_header->hdr_len))
        goto inhdr_error;

    icing_header = icing_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) icing_header, icing_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(icing_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (icing_header->hdr_len))
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

    icing_header = icing_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + icing_header->hdr_len;

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

static bool proof_verification(struct ICINGHeader *icing_header, struct PathValidationStructure *pvs, struct shash_desc* hash_api, struct shash_desc* hmac_api) {

    // 1. 变量定义
    bool result;
    int index;
    int current_node_id = pvs->node_id;
    int current_path_index = icing_header->current_path_index;
    int source = icing_header->source;
    struct ICINGHop *path = (struct ICINGHop *) (get_icing_path_start_pointer(icing_header));
    struct ICINGProof *proof_list = (struct ICINGProof *) (get_icing_proof_start_pointer(icing_header));
    // 2.计算哈希
    unsigned char *static_fields_hash = calculate_icing_hash(hash_api, icing_header);
    // 3.进行校验
    char key[20];
    // 首先进行 ai 的计算
    snprintf(key, sizeof(key), "poc-%d", pvs->node_id);
    unsigned char *ai_result = calculate_hmac(hmac_api,
                                              static_fields_hash,
                                              HASH_OUTPUT_LENGTH,
                                              (unsigned char *) key,
                                              (int) strlen(key));

    // 首先计算源和当前节点的 hmac
    snprintf(key, sizeof(key), "key-%d-%d", source, current_node_id);
    unsigned char *hmac_result_final = calculate_hmac(hmac_api,
                                                      static_fields_hash,
                                                      HASH_OUTPUT_LENGTH,
                                                      (unsigned char *) key,
                                                      (int) (strlen(key)));

    // 将 ai 和 hmac 进行异或者
    memory_xor(hmac_result_final, ai_result, ICING_PROOF_LENGTH);

    if (0 == current_path_index) {
        result = memory_compare((unsigned char *) (&proof_list[current_path_index]),
                                hmac_result_final,
                                ICING_PROOF_LENGTH);
    } else {
        for (index = 0; index < current_path_index; index++) {
            // 获取上游节点 id
            __u32 upstream_node = path[index].node_id;
            snprintf(key, sizeof(key), "key-%d-%d", upstream_node, current_node_id);
            unsigned char *hmac_result_temp = calculate_hmac(hmac_api,
                                                             static_fields_hash,
                                                             HASH_OUTPUT_LENGTH,
                                                             (unsigned char *) key,
                                                             (int) (strlen(key)));
            memory_xor(hmac_result_final, hmac_result_temp, ICING_PROOF_LENGTH);
            kfree(hmac_result_temp);
        }
        result = memory_compare((unsigned char *) (&proof_list[current_path_index]),
                                hmac_result_final,
                                ICING_PROOF_LENGTH);
    }
    kfree(ai_result);
    kfree(hmac_result_final);
    kfree(static_fields_hash);
    return result;
}

static void proof_update(struct ICINGHeader *icing_header, struct PathValidationStructure *pvs, struct shash_desc* hash_api, struct shash_desc* hmac_api) {
    // 索引
    int index;
//    // 获取 hash api
//    struct shash_desc *hash_api = pvs->hash_api;
//    // 获取 hmac_api
//    struct shash_desc *hmac_api = pvs->hmac_api;
    // 当前路径索引
    int current_path_index = icing_header->current_path_index;
    // 当前节点 id
    int current_node_id = pvs->node_id;
    // 路径长度
    int path_length = icing_header->length_of_path;
    // 路径和验证字段列表
    struct ICINGHop *path = (struct ICINGHop *) (get_icing_path_start_pointer(icing_header));
    struct ICINGProof *proof_list = (struct ICINGProof *) (get_icing_proof_start_pointer(icing_header));
    // 获取静态字段的哈希
    unsigned char *static_fields_hash = calculate_icing_hash(hash_api, icing_header);
    // 对称密钥
    char symmetric_key[20];
    // 遍历更新下游节点的 proof 字段
    for (index = current_path_index + 1; index < path_length; index++) {
        int downstream_node_id = path[index].node_id;
        snprintf(symmetric_key, sizeof(symmetric_key), "key-%d-%d", current_node_id, downstream_node_id);
        unsigned char *hmac_result = calculate_hmac(hmac_api,
                                                    static_fields_hash,
                                                    HMAC_OUTPUT_LENGTH,
                                                    (unsigned char *) symmetric_key,
                                                    (int) (strlen(symmetric_key)));
        memory_xor((unsigned char *) (&(proof_list[index])), hmac_result, ICING_PROOF_LENGTH);
        kfree(hmac_result);
    }
    kfree(static_fields_hash);
}

int icing_forward_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                          struct net_device *in_dev, u64* intermediate_verification_time_elapsed,  u64* destination_verification_time_elapsed) {

    // 初始化变量
    int index;
    int result = NET_RX_DROP;
    bool verification_result = false;
    int current_node_id = pvs->node_id;
    struct ICINGHeader *icing_header = icing_hdr(skb);
    int destination = icing_header->dest;
    struct ICINGHop *path = (struct ICINGHop *) get_icing_path_start_pointer(icing_header);
    int current_path_index = icing_header->current_path_index;
    int current_link_identifier = path[current_path_index].link_id;
    bool is_destination = current_node_id == destination;


    // 创建新的 hash hmac
    // -----------------------------------------------
//    struct pv_struct p = create_pv_struct(true, true, false, NULL);
    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // -----------------------------------------------
    // u64 start_time = ktime_get_real_ns();
    // 进行上游节点是否正确转发的校验
    if(is_destination){
        u64 start_verification_time = ktime_get_real_ns();
        verification_result = proof_verification(icing_header, pvs, p->hash_api, p->hmac_api);
        if(verification_result){
            result = NET_RX_SUCCESS;
        } else {
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            result = NET_RX_DROP;
        }
        *destination_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
    } else {
        u64 start_verification_time = ktime_get_real_ns();
        verification_result = proof_verification(icing_header, pvs, p->hash_api, p->hmac_api);

        if(verification_result){
            result = NET_RX_DROP;
            // 进行凭证的更新
            proof_update(icing_header, pvs, p->hash_api, p->hmac_api);
            *intermediate_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
            // 进行 current_path_index 的更新
            icing_header->current_path_index += 1;
            // 计算校验和
            icing_send_check(icing_header);
            // 更新完成之后遍历接口表准备进行数据包的发送
            for (index = 0; index < pvs->abit->number_of_interfaces; index++) {
                struct InterfaceTableEntry *ite = pvs->abit->interfaces[index];
                if (current_link_identifier == ite->link_identifier) {
                    // 进行转发
                    pv_packet_forward(skb, ite, current_ns);
                }
            }
        } else {
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            result = NET_RX_DROP;
        }

    }

//    free_pv_struct(&p);
    put_cpu_ptr(p);

    return result;
}