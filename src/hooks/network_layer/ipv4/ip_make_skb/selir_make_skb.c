#include "api/test.h"
#include "structure/namespace/namespace.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/path_validation_sock_structure.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"

/**
 * 进行 selir 头部的大小的获取
 * selir 头部构造如下 (标准头部) / (pvf_effective_bytes) / (bf_effective_bytes) / dest1 / dest2 ....
 * @param rcr 路由计算结果
 * @param pvs 路径验证结构体
 * @return
 */
static int get_selir_header_size(struct RoutingCalcRes *rcr, struct PathValidationStructure *pvs) {
    // 如果已经发送包 ---> 包的组成格式: header / datahash / sessionid / timestamp / pvf_bitset / ppf_bitset / destinations
    return sizeof(struct SELiRHeader) +
           sizeof(struct SELiRPvf) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf) +
           pvs->bloom_filter->bf_effective_bytes;
}

/**
 * 进行 selir 头部的大小的获取
 * @param sk
 * @param fl4
 * @param getfrag
 * @param from
 * @param length
 * @param transhdrlen
 * @param ipc
 * @param cork
 * @param flags
 * @param rcr
 * @param encryption_time_elapsed
 * @return
 */
struct sk_buff *self_defined_selir_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            int getfrag(void *from, char *to, int offset,
                                                        int len, int odd, struct sk_buff *skb),
                                            void *from, int length, int transhdrlen,
                                            struct ipcm_cookie *ipc,
                                            struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr,
                                            u64* encryption_time_elapsed) {
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
    err = self_defined_ip_setup_cork(sk, cork, ipc, rcr);
    if (err) {
        return ERR_PTR(err);
    }

    int lir_header_size = get_selir_header_size(rcr, pvs);
    //    printk(KERN_EMERG "selir header size: %d\n", lir_header_size);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, lir_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__selir_make_skb(sk, fl4, &queue, cork, rcr, encryption_time_elapsed);
}


/**
 * 进行 pvf 字段的填充
 * @param hmac_api hmac_api 进行 mac 计算的 api
 * @param pvf_start_pointer pvf 起始指针
 * @param static_fields_hash 静态字段哈希
 * @param destination_session_key 目的节点会话密钥
 */
static void fill_pvf_fields(struct shash_desc *hmac_api,
                            unsigned char *pvf_start_pointer,
                            unsigned char *static_fields_hash,
                            unsigned char *destination_session_key) {
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    static_fields_hash,
                                                    HASH_OUTPUT_LENGTH,
                                                    destination_session_key,
                                                    HMAC_OUTPUT_LENGTH);
    memcpy(pvf_start_pointer, pvf_hmac_result, PVF_LENGTH);
    kfree(pvf_hmac_result);
}

/**
 * 进行 ppf 字段的填充
 * @param rte 单播路由
 * @param pvs 路径验证数据结构
 * @param pvss socket 数据结构
 * @param pvf_start_pointer pvf 起始指针
 * @param static_fields_hash 静态字段哈希
 */
static void fill_ppf_for_single_route(struct RoutingTableEntry *rte,
                                      struct PathValidationStructure *pvs,
                                      struct PathValidationSockStructure *pvss,
                                      unsigned char* pvf_start_pointer,
                                      unsigned char* static_fields_hash) {

    int index;
    // 首先计算一个 combination
    unsigned char concatenation[PVF_LENGTH + HASH_OUTPUT_LENGTH] = {0};  // 这里使用的是全长的 hash 而不是截断的 hash
    memcpy(concatenation, pvf_start_pointer, PVF_LENGTH);
    memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_OUTPUT_LENGTH);

    // 接着使用第一个节点的 key 进行 pvf 的计算
    unsigned char* next_pvf = calculate_hmac(pvs->hmac_api,
                                             concatenation,
                                             PVF_LENGTH + HASH_OUTPUT_LENGTH,
                                             pvss->session_keys[0],
                                             HMAC_OUTPUT_LENGTH);


    // 将这个 PVF 放到布隆过滤器之中去
    push_element_into_bloom_filter(pvs->bloom_filter, next_pvf, PVF_LENGTH);

    // 进行所有的节点的遍历
    for (index = 1; index < rte->path_length - 1; index++) {
        // 拿到 session key
        unsigned char *session_key = pvss->session_keys[index]; // session_key 会话密钥
        // 进行拼接
        memcpy(concatenation, next_pvf, PVF_LENGTH);
        memcpy(concatenation + PVF_LENGTH, static_fields_hash, HASH_OUTPUT_LENGTH);
        // 进行 hmac 的计算
        unsigned char *hmac_result = calculate_hmac(pvs->hmac_api,
                                                    concatenation,
                                                    PVF_LENGTH + HASH_OUTPUT_LENGTH,
                                                    session_key,
                                                    HMAC_OUTPUT_LENGTH);

        // 进行 next pvf 的释放
        kfree(next_pvf);

        // 更新 next_pvf
        next_pvf = hmac_result;

        // 将 hmac_result 插入到 bf 之中
        push_element_into_bloom_filter(pvs->bloom_filter, hmac_result, PVF_LENGTH);
    }
    if(next_pvf) {
        kfree(next_pvf);
    }
}

/**
 * 进行 PPF 字段的填充
 * @param selir_header selir 的头部
 * @param rcr 路由计算结果
 * @param pvs 路径验证结构体
 * @param pvss session 结构体
 */
static void fill_ppf_fields(struct RoutingCalcRes *rcr,
                            struct PathValidationStructure *pvs,
                            struct PathValidationSockStructure *pvss,
                            unsigned char *ppf_start_pointer,
                            unsigned char *pvf_start_pointer,
                            unsigned char *static_fields_hash) {
    // 这里还是进行单条路由的处理
    struct RoutingTableEntry* rte = rcr->rtes[0];
    // 处理单条路由
    fill_ppf_for_single_route(rte, pvs, pvss, pvf_start_pointer, static_fields_hash);
    // 将 bf 复制到 ppf 的位置
    memcpy(ppf_start_pointer, pvs->bloom_filter->bitset, pvs->bloom_filter->bf_effective_bytes);
    // 进行 bf 的重置
    reset_bloom_filter(pvs->bloom_filter);
}


static void fill_meta_data(struct SELiRHeader *selir_header,
                           unsigned char *static_fields_hash,
                           struct SessionID session_id,
                           time64_t timestamp) {
    unsigned char *hash_start_pointer = get_selir_hash_start_pointer(selir_header);
    unsigned char *session_id_start_pointer = get_selir_session_id_start_pointer(selir_header);
    unsigned char *timestamp_start_pointer = get_selir_timestamp_start_pointer(selir_header);
    memcpy(hash_start_pointer, static_fields_hash, HASH_LENGTH);
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
    memcpy(timestamp_start_pointer, &(timestamp), sizeof(time64_t));
}

struct sk_buff *self_defined__selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                             struct sk_buff_head *queue, struct inet_cork *cork,
                                             struct RoutingCalcRes *rcr,
                                             u64* encryption_time_elapsed) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct SELiRHeader *selir_header;
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    unsigned char *bloom_pointer_start = NULL;
    unsigned char *dest_pointer_start = NULL;

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
    selir_header = selir_hdr(skb); // 创建 header
    selir_header->version = SELIR_VERSION_NUMBER; // 版本 (字段1)
    selir_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    selir_header->ttl = ttl; // ttl (字段3)
    selir_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    selir_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    selir_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    selir_header->check = 0; // 校验和字段 (字段7)
    selir_header->source = rcr->source; // 设置源 (字段8)
    selir_header->hdr_len = get_selir_header_size(rcr, pvs); // 设置数据包头部长度 (字段9)
    selir_header->tot_len = htons(skb->len); // tot_len 字段 10
    selir_header->ppf_len = pvs->bloom_filter->bf_effective_bytes; // ppf 长度
    selir_header->dest_len = rcr->user_space_info->number_of_destinations; // 目的数量
    // ---------------------------------------------------------------------------------------

    // 填充其余的部分
    // ---------------------------------------------------------------------------------------
    // 0. 拿到 pvss
    struct PathValidationSockStructure *pvss = (struct PathValidationSockStructure *) (sk->path_validation_sock_structure);
    // 1. 首先计算哈希
    unsigned char *static_fields_hash = calculate_selir_hash(pvs->hash_api, selir_header);
    // 2. 进行元数据的填充
    fill_meta_data(selir_header, static_fields_hash, pvss->session_id, pvss->timestamp);
    // 3. 填充 pvf 字段
    unsigned char *pvf_start_pointer = get_selir_pvf_start_pointer(selir_header);
    unsigned char* ppf_start_pointer = get_selir_ppf_start_pointer(selir_header);
    u64 start_time = ktime_get_real_ns();
    fill_pvf_fields(pvs->hmac_api,
                    pvf_start_pointer,
                    static_fields_hash,
                    pvss->session_keys[rcr->rtes[0]->path_length - 1]);
    // 4. 填充 ppf 字段
    fill_ppf_fields(rcr, pvs, pvss, ppf_start_pointer, pvf_start_pointer, static_fields_hash);
    *encryption_time_elapsed = ktime_get_real_ns() - start_time;
    // 5. 在最后进行静态哈希的释放
    kfree(static_fields_hash);
    // ---------------------------------------------------------------------------------------
    // 等待一切就绪之后计算 selir_send_check
    selir_send_check(selir_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
    // ---------------------------------------------------------------------------------------
}