#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "structure/namespace/namespace.h"
#include "structure/session/session_table.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include <net/inet_ecn.h>
#include <linux/inetdevice.h>

int opt_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed) {
    struct net *current_ns = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    struct OptHeader *opt_header = opt_hdr(skb);
    // 1. 初始化变量
    int process_result;
    // 2. 进行初级的校验
    skb = opt_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    // 3. 进行不同的数据包的处理
    process_result = opt_forward_data_packets(skb, pvs, current_ns, intermediate_verification_time_elapsed, destination_verification_time_elapsed);

    // 5. 进行数据包本地的处理
    if (NET_RX_SUCCESS == process_result) {
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, opt_header->protocol, receive_interface_address);
    }
    return 0;
}

// 数据包处理逻辑
// ---------------------------------------------------------------------------------------------------------------------------------------

/**
 * 进行上游节点是否正确转发的校验
 * @param opt_header 同步
 * @param pvs 路径验证结构体
 * @param ste 会话表项
 * @param session_key 会话密钥
 * @return 返回是否验证成功
 */
static bool proof_verification(struct OptHeader *opt_header,
                               struct SessionTableEntry *ste,
                               unsigned char *session_key,
                               struct shash_desc* hmac_api) {
    // 1. 获取包内指针
    unsigned char *pvf_start_pointer = get_other_opt_pvf_start_pointer(opt_header);
    unsigned char *hash_start_pointer = get_other_opt_hash_start_pointer(opt_header);
    time64_t * time_stamp_pointer = (time64_t *) get_other_opt_timestamp_start_pointer(opt_header);
    struct OptOpv *opvs = (struct OptOpv *) (get_other_opt_opv_start_pointer(opt_header));
    int current_path_index = opt_header->current_path_index;
    // 2. 计算 combination
    unsigned char combination[100] = {0};
    // 2.1 拼接前一个 pvf
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    // 2.2 拼接 data hash
    memcpy(combination + PVF_LENGTH, hash_start_pointer, HASH_LENGTH);
    // 2.2 拼接前驱节点
    *((int *) (combination + PVF_LENGTH + HASH_LENGTH)) = ste->previous_node;
    // 2.4 拼接 timestamp
    *((time64_t *) (combination + PVF_LENGTH + HASH_LENGTH + sizeof(int))) = (*time_stamp_pointer);
    // 3. 利用 session_key 计算 opv
    unsigned char *hmac_result = calculate_hmac(hmac_api,
                                                (unsigned char *) combination,
                                                PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                session_key,
                                                HMAC_OUTPUT_LENGTH);

    // 4. 进行比较, 判断是否验证成功
    bool result = memory_compare((unsigned char *) (&(opvs[current_path_index])), hmac_result, OPV_LENGTH);

    // 5. 进行 hmac_result 的释放 / session_key 先不进行释放, 一会儿还要用来进行 pvf 的更新。
    kfree(hmac_result);

    // 6. 进行结果的返回
    return result;
}

/**
 * 进行 proof 的更新
 * @param opt_header opt 头部
 * @param hmac_api hmac api
 * @param session_key 会话的密钥
 */
static void proof_update(struct OptHeader *opt_header, struct shash_desc *hmac_api, unsigned char *session_key) {
    // 1. 获取包内指针
    unsigned char *pvf_start_pointer = get_other_opt_pvf_start_pointer(opt_header);
    // 2. 利用 session_key 来计算 mac
    unsigned char *hmac_result = calculate_hmac(hmac_api,
                                                pvf_start_pointer,
                                                PVF_LENGTH,
                                                session_key,
                                                HMAC_OUTPUT_LENGTH);
    // 3. 更新到 pvf 之中
    memcpy(pvf_start_pointer, hmac_result, PVF_LENGTH);

    // 4. 进行 hmac_result 的 free
    kfree(hmac_result);
}


/**
 * 目的节点处理数据包逻辑
 * @return
 */
static bool destination_process_data_packets(struct OptHeader *opt_header,
                                            struct SessionTableEntry *ste,
                                            struct shash_desc* hmac_api) {
    // 索引
    int index;
    // 获取 hash 起始指针
    unsigned char *hash_start_pointer = get_other_opt_hash_start_pointer(opt_header);
    // 获取 pvf 起始指针
    unsigned char *pvf_start_pointer = get_other_opt_pvf_start_pointer(opt_header);
    // 获取时间起始指针
    time64_t * time_stamp_pointer = (time64_t *) (get_other_opt_timestamp_start_pointer(opt_header));
    // 获取 opvs
    struct OptOpv *opvs = (struct OptOpv *) (get_other_opt_opv_start_pointer(opt_header));
    // 获取目的节点 session_key
    unsigned char *session_key = ste->session_keys[0];

    // 完成 PVF 的计算和校验
    // ------------------------------------------------------------------------------------------------
    // 在外侧首先计算一次 (使用的是 MACkd)
    unsigned char *hmac_result = calculate_hmac(hmac_api,
                                                hash_start_pointer,
                                                HASH_LENGTH,
                                                session_key,
                                                HMAC_OUTPUT_LENGTH);

    // 接着进行循环计算
    for (index = 1; index < ste->encrypt_len; index++) {
        session_key = ste->session_keys[index];
        unsigned char *tmp = calculate_hmac(hmac_api,
                                            hmac_result,
                                            PVF_LENGTH,
                                            session_key,
                                            HMAC_OUTPUT_LENGTH);
        kfree(hmac_result);
        hmac_result = tmp;
    }

    // 最终得到的 hmac_result 和数据包内的 pvf 进行比较
    bool pvf_result = memory_compare(pvf_start_pointer, hmac_result, PVF_LENGTH);

    // 计算完成之后完成 hmac_result 的释放
    kfree(hmac_result);
    // ------------------------------------------------------------------------------------------------

    // 计算 combination
    // ------------------------------------------------------------------------------------------------
    unsigned char combination[100] = {0};
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(combination + PVF_LENGTH, hash_start_pointer, HASH_LENGTH);
    *((int *) (combination + PVF_LENGTH + HASH_LENGTH)) = ste->previous_node;
    *((time64_t *) (combination + PVF_LENGTH + HASH_LENGTH + sizeof(int))) = (*time_stamp_pointer);
    // ------------------------------------------------------------------------------------------------


    // 完成 OPV 的计算和校验
    // ------------------------------------------------------------------------------------------------
    hmac_result = calculate_hmac(hmac_api,
                                 (unsigned char *) combination,
                                 PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                 ste->session_keys[0],
                                 HMAC_OUTPUT_LENGTH);

    bool opv_result = memory_compare((unsigned char *) (&(opvs[opt_header->current_path_index])), hmac_result,
                                     OPV_LENGTH);
    // 计算完成之后进行 hmac_result 的释放
    kfree(hmac_result);
    // ------------------------------------------------------------------------------------------------

    // 根据结果决定数据包的处理结果
    if (pvf_result && opv_result) {
        // LOG_WITH_PREFIX("destination validation succeed");
        return true;
    } else {
        // LOG_WITH_PREFIX("destination validation failed");
        return false;
    }
}

/**
 * 中间节点处理数据包逻辑
 * @param skb 数据包
 * @param opt_header
 * @param pvs 路径验证数据结构
 * @param ste 会话表项
 * @param session_id 会话 id
 * @param current_node_id 当前节点 id
 * @param current_ns 当前的网络命名空间
 * @return
 */
static bool intermediate_process_data_packets(struct sk_buff *skb,
                                              struct OptHeader *opt_header,
                                              struct SessionTableEntry *ste,
                                              struct net *current_ns,
                                              struct shash_desc* hmac_api,
                                              u64* intermediate_verification_time_elapsed) {
    u64 start_verification_time = ktime_get_real_ns();
    bool verification_result = false;

    // 1.2 方式2: 找到 session_key
    unsigned char *session_key = ste->session_key;
    // 2.进行结果的验证
    bool result = proof_verification(opt_header, ste, session_key, hmac_api);
    // 3.进行字段的更新
    if (result) { // 如果验证是成功的, 则进行字段的更新
        proof_update(opt_header, hmac_api, session_key);
        *intermediate_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
        opt_header->current_path_index += 1;
        // 6. 进行校验和的更新
        opt_send_check(opt_header);
        // 7. 进行相应的转发
        if (NULL != ste) {
            pv_packet_forward(skb, ste->ite, current_ns);
            verification_result = true;
        }
    } else { // 如果验证是失败的, 则直接进行包的丢弃
        verification_result = false;
    }
    return verification_result;
}


/**
 * 进行 opt 数据包的转发
 * @param skb 数据包
 * @param pvs 路径验证数据结构
 * @param current_ns 当前的网络命名空间
 * @param in_dev 入接口
 * @return
 */
int opt_forward_data_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed) {
    // 0.最终结果
    int final_result = NET_RX_DROP;
    // 1.是否本地提交
    bool local_deliver;
    // 2.找到 opt_header
    struct OptHeader *opt_header = opt_hdr(skb);
    // 3.拿到目的节点
    int destination = opt_header->dest;
    // 5.拿到 session_id
    struct SessionID *session_id = (struct SessionID *) get_other_opt_session_id_start_pointer(opt_header);
    // 6.根据 session_id 拿到对应的表项
    struct SessionTableEntry *ste = find_ste_in_hbst(pvs->hbst, session_id);
    // 6.判断是否到达目的节点
    local_deliver = pvs->node_id == destination;
    // 7. 获取 hash_api 和 hmac_api
    // ---------------------------------------------------------------------------------------
    // struct pv_struct p = create_pv_struct(false, true, false, NULL);
    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // ---------------------------------------------------------------------------------------
    if (local_deliver) {
        u64 start_verification_time = ktime_get_real_ns();
        bool result = destination_process_data_packets(opt_header, ste, p->hmac_api);
        if(result) {
            final_result = NET_RX_SUCCESS;
        } else {
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            final_result = NET_RX_DROP;
        }
        *destination_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
    } else {
        // 如果是中间节点, 有中间节点的处理
        bool result = intermediate_process_data_packets(skb, opt_header, ste, current_ns, p->hmac_api, intermediate_verification_time_elapsed);
        // 如果为false则需要进行丢包, true 的话已经转发走了
        if(!result){
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            final_result = NET_RX_DROP;
        } else {
            final_result = NET_RX_DROP;
        }
    }
//    free_pv_struct(&p);
    put_cpu_ptr(p);

    return final_result;
}

// ---------------------------------------------------------------------------------------------------------------------------------------

struct sk_buff *opt_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct OptHeader *opt_header;
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
    opt_header = opt_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (opt_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, opt_header->hdr_len))
        goto inhdr_error;

    opt_header = opt_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) opt_header, opt_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(opt_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (opt_header->hdr_len))
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

    opt_header = opt_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + opt_header->hdr_len;

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