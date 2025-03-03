#include "api/test.h"
#include "structure/namespace/namespace.h"
#include "structure/header/opt_header.h"
#include "structure/path_validation_sock_structure.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

/**
 * 获取数据包的大小 (针对)
 * @param rcr 路由计算结果
 * @param pvs 路径验证数据结构
 * @param sent_first_packet 是否已经发送过了第一个包
 * @return 数据包的大小
 */
static int get_opt_header_size(struct RoutingCalcRes *rcr) {
    // 拿到唯一的路由条目
    struct RoutingTableEntry *rte = rcr->rtes[0];
    // 拿到路径
    int path_length = rte->path_length;
    // 包的组成格式: opt_header | data_hash | session_id | timestamp | pvf | opvs
    return sizeof(struct OptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct OptPvf) +
           sizeof(struct OptOpv) * path_length;
}


/**
 * 进行 data_hash, session_id 以及 timestamp 的填充
 * @param opt_header opt 首部
 * @param static_fields_hash 静态字段的哈希
 * @param session_id 会话 id
 * @param timestamp 时间戳
 */
static void fill_meta_data(struct OptHeader *opt_header, unsigned char *static_fields_hash, struct SessionID session_id,
                           time64_t timestamp) {
    unsigned char *hash_start_pointer = get_other_opt_hash_start_pointer(opt_header);
    unsigned char *session_id_start_pointer = get_other_opt_session_id_start_pointer(opt_header);
    unsigned char *timestamp_start_pointer = get_other_opt_timestamp_start_pointer(opt_header);
    memcpy(hash_start_pointer, static_fields_hash, HASH_LENGTH);
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
    memcpy(timestamp_start_pointer, &(timestamp), sizeof(time64_t));
}

/**
 * 进行 pvf 字段的填充
 * @param hmac_api hmac api
 * @param pvf_start_pointer pvf 起始指针
 * @param static_fields_hash 静态字段哈希
 * @param dest_session_key 目的节点的会话密钥
 * @return 计算好的 pvf0
 */
static unsigned char *initialize_pvf(struct shash_desc *hmac_api,
                                     unsigned char *pvf_start_pointer,
                                     unsigned char *static_fields_hash,
                                     unsigned char *dest_session_key) {
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    static_fields_hash,
                                                    HASH_LENGTH, // 注意其他的数据接收着也只能拿到 HASH_LENGTH 16 而不是完整的 20 bytes.
                                                    dest_session_key,
                                                    HMAC_OUTPUT_LENGTH);
    memcpy(pvf_start_pointer, pvf_hmac_result, PVF_LENGTH);
    return pvf_hmac_result;
}


/**
 *
   初始化 opvs
   计算流程: A->B->C
   首先计算 PVF0 = MACKC(H)
   然后计算 OPV1 = MACKB(PVF0 || DATAHASH || Source = A || TimeStamp)
   然后计算 PVF1 = MACKB(MACKC(H))
   然后计算 OPV2 = MACKC(PVF1 || DATAHASH || B || TimeStamp)
 * 进行 opvs 的初始化
 * @param hmac_api hmac_api
 * @param opvs opvs
 * @param pvf_hmac_result pvf_hmac 结果
 * @param static_fields_hash 静态字段哈希
 * @param rte 路由表项
 * @param pvss 存储会话信息的结构体
 * @return
 */
static void initialize_opvs(struct shash_desc *hmac_api,
                            struct OptOpv *opvs,
                            unsigned char *pvf_hmac_result,
                            unsigned char *static_fields_hash,
                            struct RoutingTableEntry *rte,
                            struct PathValidationSockStructure *pvss) {
    // 1.索引
    int index;
    // 2.opv
    unsigned char *opv_i = NULL;
    // 3. 循环产生 opv_i
    for (index = 0; index < rte->path_length; index++) {
        // 3.1 计算 combination
        unsigned char combination[100] = {0};
        // 3.1.1 拼接前一个 pvf
        memcpy(combination, pvf_hmac_result, PVF_LENGTH); // 从 20 字节之中的 HMAC_OUTPUT 之中 拷贝 16 字节
        // 3.1.2 拼接 data_hash
        memcpy(combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH); // 从 20 字节之中的 HASH 之中拷贝 16 字节
        // 3.1.3 拼接前驱节点
        if (index == 0) {
            // 拼接源
            *((int *) (combination + PVF_LENGTH + HASH_LENGTH)) = rte->source_id;
        } else {
            // 拼接前驱
            *((int *) (combination + PVF_LENGTH + HASH_LENGTH)) = rte->node_ids[index - 1];
        }
        // 3.1.4 拼接 timestamp
        *((time64_t *) (combination + PVF_LENGTH + HASH_LENGTH + sizeof(int))) = pvss->timestamp;



        // 3.2 拿到中间节点的 key
        unsigned char *intermediate_session_key = pvss->session_keys[index];


        // 3.2 进行 opv_i 的计算, 并拷贝到相应的位置
        opv_i = calculate_hmac(hmac_api,
                               combination,
                               PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                               intermediate_session_key,
                               HMAC_OUTPUT_LENGTH);





        // 3.4 拷贝到指定的位置处
        memcpy(&(opvs[index]), opv_i, OPV_LENGTH);




        // 3.5 拷贝完成之后进行释放
        kfree(opv_i);

        // 3.6 如果已经到了最后一个 opv, 其后续没有 pvf 需要计算了
        if (index == rte->path_length - 1) {
            break;
        } else {
            // 3.6 如果还没有到最后一个 opv, 还需要ji
            unsigned char *tmp = calculate_hmac(hmac_api,
                                                pvf_hmac_result,
                                                PVF_LENGTH,
                                                intermediate_session_key,
                                                HMAC_OUTPUT_LENGTH);
            // 进行 hmac 的释放
            if(NULL != pvf_hmac_result) {
                kfree(pvf_hmac_result);
                pvf_hmac_result = NULL;
            }

            // 将刚创建的 hmac 进行赋值
            pvf_hmac_result = tmp;
        }
    }
    // 4. 进行 hash 以及 hmac 的释放
    if(NULL != static_fields_hash){
        kfree(static_fields_hash);
    }
    if(NULL != pvf_hmac_result) {
        kfree(pvf_hmac_result);
    }
}

/**
 * 填充后续数据包的头部
 * @param opt_header opt 首部
 * @param rte 路由表项
 * @param pvs 路径验证数据结构
 * @param pvss 路径验证 socket 数据结构
 */
static void fill_data_packet_fields(struct OptHeader *opt_header,
                                    struct RoutingTableEntry *rte,
                                    struct PathValidationStructure *pvs,
                                    struct PathValidationSockStructure *pvss) {
    // 1. 拿到 hash_api 和 hmac_api
    struct shash_desc *hash_api = pvs->hash_api;
    struct shash_desc *hmac_api = pvs->hmac_api;
    // 2. 首先计算哈希
    unsigned char *static_fields_hash = calculate_opt_hash(hash_api, opt_header);
    // 3. 为 [1] data hash [2] session_id [3] timestamp 进行赋值
    fill_meta_data(opt_header, static_fields_hash, pvss->session_id, pvss->timestamp);
    // 4. 初始化 pvf 即 pvf0
    int path_length = rte->path_length;
    unsigned char *pvf_start_pointer = get_other_opt_pvf_start_pointer(opt_header);
    unsigned char *dest_session_key = pvss->session_keys[path_length - 1];
    unsigned char *pvf_hmac_result = initialize_pvf(hmac_api, pvf_start_pointer, static_fields_hash, dest_session_key);
    // 5. 初始化 opv
    struct OptOpv *opt_opvs = (struct OptOpv *) (get_other_opt_opv_start_pointer(opt_header));
    initialize_opvs(hmac_api, opt_opvs, pvf_hmac_result, static_fields_hash, rte, pvss);
}

/**
 * 进行 session_id 的计算
 * @return session_id
 */
static unsigned char *calculate_session_id(struct shash_desc *hash_api,
                                           struct RoutingCalcRes *rcr,
                                           struct RoutingTableEntry *rte,
                                           time64_t current_time) {
    unsigned char *data[4] = {
            (unsigned char *) (&(rcr->source)),
            (unsigned char *) (rte->link_identifiers),
            (unsigned char *) (rte->node_ids),
            (unsigned char *) (&current_time)
    };
    int lengths[4] = {
            sizeof(int), // source 的字节数
            sizeof(int) * rte->path_length, // rte->link_identifiers 的字节数
            sizeof(int) * rte->path_length,  // rte->node_ids 的字节数
            sizeof(time64_t) // 时间的大小
    };
    unsigned char *session_id = calculate_hash_from_multiple_segments(hash_api, data, lengths, 4);
    return session_id;
}


struct sk_buff *self_defined_opt_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          int getfrag(void *from, char *to, int offset,
                                                      int len, int odd, struct sk_buff *skb),
                                          void *from, int length, int transhdrlen,
                                          struct ipcm_cookie *ipc,
                                          struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr, u64* encryption_time_elapsed) {
    struct sk_buff_head queue;
    int err;

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

    // 进行包头的大小的获取, 不同类型的包不一样
    int opt_header_size = get_opt_header_size(rcr);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, opt_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__opt_make_skb(sk, fl4, &queue, cork, rcr, encryption_time_elapsed);
}

struct sk_buff *self_defined__opt_make_skb(struct sock *sk,
                                           struct flowi4 *fl4,
                                           struct sk_buff_head *queue,
                                           struct inet_cork *cork,
                                           struct RoutingCalcRes *rcr,
                                           u64* encryption_time_elapsed) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct OptHeader *opt_header;
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    struct RoutingTableEntry *rte = rcr->rtes[0];

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

    // 头部基本部分填充
    // ---------------------------------------------------------------------------------------
    opt_header = opt_hdr(skb);
    opt_header->version = OPT_DATA_VERSION_NUMBER; // 版本 (字段1)
    opt_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    opt_header->ttl = ttl; // ttl (字段3)
    opt_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    opt_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    opt_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    opt_header->check = 0; // 校验和字段 (字段7)
    opt_header->source = rcr->source; // 设置源 (字段8)
    opt_header->dest = rcr->user_space_info->destinations[0]; // 设置目的 (字段9)
    opt_header->hdr_len = get_opt_header_size(rcr); // 设置数据包总长度 (字段10)
    opt_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    opt_header->current_path_index = 0; // 当前的索引 (字段12)
    // ---------------------------------------------------------------------------------------

    // 直接从 sock 之中所包村的 path_validation_sock_structure 之中拿到 session_id
    // ---------------------------------------------------------------------------------------
    struct SessionID session_id;
    session_id = ((struct PathValidationSockStructure *) (sk->path_validation_sock_structure))->session_id; // 从 socket 之中直接拿到 session_id
    // ---------------------------------------------------------------------------------------

    // 头部后续部分初始化
    // ---------------------------------------------------------------------------------------
    // 拿到 path_validation_sock_structure
//    u64 start = ktime_get_real_ns();
    struct PathValidationSockStructure *pvss = (struct PathValidationSockStructure *) (sk->path_validation_sock_structure);
    fill_data_packet_fields(opt_header, rcr->rtes[0], pvs, pvss);
//    *encryption_time_elapsed = ktime_get_real_ns() - start;
    // ---------------------------------------------------------------------------------------

    // 等待一切就绪后计算 check
    opt_send_check(opt_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
}