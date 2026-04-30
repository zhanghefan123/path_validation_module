#include "tools/tools.h"
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "structure/header/fast_selir_header.h"
#include "structure/path_validation_sock_structure.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

static int get_fast_selir_header_size(struct PathValidationStructure *pvs) {
    return sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf) +
           sizeof(struct EncPvf) +
           pvs->bloom_filter->bf_effective_bytes;
}


struct sk_buff *self_defined_fast_selir_make_skb(struct sock *sk,
                                                 struct flowi4 *fl4,
                                                 int getfrag(void *from, char *to, int offset,
                                                             int len, int odd, struct sk_buff *skb),
                                                 void *from, int length, int transhdrlen,
                                                 struct ipcm_cookie *ipc,
                                                 struct inet_cork *cork, unsigned int flags,
                                                 struct RoutingCalcRes *rcr,
                                                 u64 *make_skb_time_elapsed,
                                                 u64 *enc_time_elapsed) {
    u64 start_make_skb_time = ktime_get_real_ns();
    struct sk_buff_head queue;
    int err;
    struct net *current_ns = sock_net(sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);

    if (flags & MSG_PROBE)
        return NULL;

    __skb_queue_head_init(&queue);

    cork->flags = 0;
    cork->addr = 0;
    cork->opt = NULL;
    err = self_defined_xx_setup_cork(sk, cork, ipc);
    if (err) {
        return ERR_PTR(err);
    }

    int lir_header_size = get_fast_selir_header_size(pvs);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr->ite, lir_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    struct sk_buff* result =  self_defined__fast_selir_make_skb(sk, fl4, &queue, cork, rcr, enc_time_elapsed);
    *make_skb_time_elapsed = ktime_get_real_ns() - start_make_skb_time;
    return result;
}


static void fill_meta_data(struct FastSELiRHeader *fast_selir_header,
                           unsigned char *static_fields_hash,
                           struct SessionID session_id,
                           time64_t timestamp) {
    unsigned char *hash_start_pointer = get_fast_selir_hash_start_pointer(fast_selir_header);
    unsigned char *session_id_start_pointer = get_fast_selir_session_id_start_pointer(fast_selir_header);
    unsigned char *timestamp_start_pointer = get_fast_selir_timestamp_start_pointer(fast_selir_header);
    memcpy(hash_start_pointer, static_fields_hash, HASH_LENGTH);
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
    memcpy(timestamp_start_pointer, &(timestamp), sizeof(time64_t));
}


static void fill_ppf_and_encpvf_for_single_route(struct RoutingTableEntry *rte,
                                                 struct PathValidationSockStructure *pvss,
                                                 unsigned char *pvf_start_pointer,
                                                 unsigned char *encpvf_start_pointer,
                                                 unsigned char *ppf_start_pointer,
                                                 unsigned char *static_fields_hash,
                                                 struct shash_desc *hmac_api,
                                                 struct BloomFilter* bloom_filter) {
    int index;
    // 首先计算一个 combination
    unsigned char concatenation[PVF_LENGTH + HASH_LENGTH] = {0};  // 这里使用的是全长的 hash 而不是截断的 hash
    memcpy(concatenation, pvf_start_pointer, PVF_LENGTH);
    memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_LENGTH);

    // 接着使用源节点后一个节点进行 pvf 的计算
    unsigned char *next_pvf = calculate_hmac(hmac_api,
                                             concatenation,
                                             PVF_LENGTH + HASH_LENGTH,
                                             pvss->session_keys[0],
                                             HMAC_OUTPUT_LENGTH);


    // 将第一个节点的 pvf 放到布隆过滤器之中去
    push_element_into_bloom_filter(bloom_filter, next_pvf, PVF_LENGTH);

    // 进行所有的节点的遍历
    for (index = 1; index < rte->path_length; index++) {
        // 目的节点
        if (index == (rte->path_length - 1)) { // 目的节点
            // 拿到 session_key
            unsigned char *session_key = pvss->session_keys[index];

            // 进行拼接
            memcpy(concatenation, next_pvf, PVF_LENGTH);
            memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_LENGTH);


            // 对最后的 next_pvf 进行加密
            unsigned char *enc_pvf = calculate_hmac(hmac_api,
                                                    concatenation,
                                                    PVF_LENGTH + HASH_LENGTH,
                                                    session_key,
                                                    HMAC_OUTPUT_LENGTH);

            // 将 enc pvf 放到对应的位置
            memcpy(encpvf_start_pointer, enc_pvf, PVF_LENGTH);

            // 进行 enc pvf 的释放
            if (enc_pvf) {
                kfree(enc_pvf);
            }

            // 进行 next_pvf 的释放
            if (next_pvf) {
                kfree(next_pvf);
            }
        } else { // 非目的节点
            // 拿到 session key
            unsigned char *session_key = pvss->session_keys[index]; // session_key 会话密钥
            // 进行拼接
            memcpy(concatenation, next_pvf, PVF_LENGTH);
            memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
            // 进行 hmac 的计算
            unsigned char *hmac_result = calculate_hmac(hmac_api,
                                                        concatenation,
                                                        PVF_LENGTH + HASH_LENGTH,
                                                        session_key,
                                                        HMAC_OUTPUT_LENGTH);

            // 进行 next pvf 的释放
            kfree(next_pvf);

            // 更新 next_pvf
            next_pvf = hmac_result;

            // 将 hmac_result 插入到 bf 之中
            push_element_into_bloom_filter(bloom_filter, hmac_result, PVF_LENGTH);
        }
    }

    // 将 bf 复制到 ppf 的位置
    memcpy(ppf_start_pointer, bloom_filter->bitset, bloom_filter->bf_effective_bytes);

    // 进行 bf 的重置
    reset_bloom_filter(bloom_filter);
}

struct sk_buff *self_defined__fast_selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                                  struct sk_buff_head *queue, struct inet_cork *cork,
                                                  struct RoutingCalcRes *rcr,
                                                  u64 *enc_time_elapsed) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct FastSELiRHeader *fast_selir_header;
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);

    __be16 df = 0;
    __u8 ttl;

    skb = __skb_dequeue(queue);
    if (!skb)
        goto out;
    tail_skb = &(skb_shinfo(skb)->frag_list);

    /* move skb->data to ip header from ext header */
    if (skb->data < skb_network_header(skb))
        __skb_pull(skb, skb_network_offset(skb));
    while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
        __skb_pull(tmp_skb, skb_network_header_len(skb));
        *tail_skb = tmp_skb;
        tail_skb = &(tmp_skb->next);
        skb->len += tmp_skb->len;
        skb->data_len += tmp_skb->len;
        skb->truesize += tmp_skb->truesize;
        tmp_skb->destructor = NULL;
        tmp_skb->sk = NULL;
    }

    /* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
     * to fragment the frame generated here. No matter, what transforms
     * how transforms change size of the packet, it will come out.
     */
    skb->ignore_df = ip_sk_ignore_df(sk);
    ttl = READ_ONCE(net->ipv4.sysctl_ip_default_ttl);

    // 进行基本头部的初始化
    // ---------------------------------------------------------------------------------------
    fast_selir_header = fast_selir_hdr(skb); // 创建 header
    fast_selir_header->version = FAST_SELIR_VERSION_NUMBER; // 版本 (字段1)
    fast_selir_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    fast_selir_header->ttl = ttl; // ttl (字段3)
    fast_selir_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    fast_selir_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    fast_selir_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    fast_selir_header->check = 0; // 校验和字段 (字段7)
    fast_selir_header->source = rcr->source; // 设置源 (字段8)
    fast_selir_header->hdr_len = get_fast_selir_header_size(pvs); // 设置数据包头部长度 (字段9)
    fast_selir_header->tot_len = htons(skb->len); // tot_len 字段 10
    fast_selir_header->ppf_len = pvs->bloom_filter->bf_effective_bytes; // ppf 长度
    fast_selir_header->dest_len = rcr->user_space_info->number_of_destinations; // 目的数量
    // ---------------------------------------------------------------------------------------

    u64 start_enc_time = ktime_get_real_ns();
    struct pv_struct* p = get_cpu_ptr(&validation_api);

    // 进行其余的部分的填充
    // ---------------------------------------------------------------------------------------
    // 0. 拿到 pvss
    struct PathValidationSockStructure *pvss = (struct PathValidationSockStructure *) (sk->path_validation_sock_structure);

    // 3. 获取各个字段的指
    unsigned char *pvf_start_pointer = get_fast_selir_pvf_start_pointer(fast_selir_header);
    unsigned char *encpvf_start_pointer = get_fast_selir_enc_pvf_start_pointer(fast_selir_header);
    unsigned char *ppf_start_pointer = get_fast_selir_ppf_start_pointer(fast_selir_header);

    // 1. 首先计算哈希
    unsigned char *static_fields_hash = calculate_fast_selir_hash(p->hash_api, fast_selir_header);
    // 2. 进行元数据的填充
    fill_meta_data(fast_selir_header, static_fields_hash, pvss->session_id, pvss->timestamp);
    // 4. 填充 pvf 字段
    memset(pvf_start_pointer, 0, PVF_LENGTH);
    // 5. 进行 ppf 和 enc_pvf 的填充
    fill_ppf_and_encpvf_for_single_route(rcr->rtes[0], pvss, pvf_start_pointer,
                                         encpvf_start_pointer, ppf_start_pointer,
                                         static_fields_hash, p->hmac_api, p->bloom_filter);

    // 进行 static_fields_hash 的释放
    kfree(static_fields_hash);

    put_cpu_ptr(p);

    *enc_time_elapsed = ktime_get_real_ns() - start_enc_time;
    // ---------------------------------------------------------------------------------------

    // 等待一切就绪之后计算 selir_send_check
    fast_selir_send_check(fast_selir_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
}