#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/namespace/namespace.h"
#include "structure/path_validation_sock_structure.h"
#include "structure/header/session_header.h"
#include "api/test.h"

static int get_session_header_size(struct RoutingCalcRes *rcr) {
    // 拿到路由条目
    struct RoutingTableEntry *rte = rcr->rtes[0];
    // 拿到路径
    int path_length = rte->path_length;
    // 返回结果
    return sizeof(struct SessionHeader) +
           sizeof(struct SessionID) +
           path_length * sizeof(struct SessionHop);
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

/**
 * 填充会话包的 session_id 字段
 * @param opt_header opt 首部
 * @param session_id session_id
 */
static void fill_session_packet_session_id(struct SessionHeader *session_header, struct SessionID session_id) {
    // 获取 session_id 起始 pointer
    unsigned char *session_id_start_pointer = get_session_setup_session_id_pointer(session_header);
    // 拷贝 session_id 到起始 pointer
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
}

/**
 * 进行 opt_path 的填充
 * @param opt_header opt 首部
 * @param rte 路由表项
 */
static void fill_session_packet_path(struct SessionHeader *session_header, struct RoutingTableEntry *rte) {
    // 索引
    int index;
    // 路径起始字段
    struct SessionHop *path = (struct SessionHop *) get_session_setup_schedule_path_start_pointer(session_header);
    // 路径长度
    int path_length = rte->path_length;
    // 进行路径的设置
    for (index = 0; index < path_length; index++) {
        // 当还没到达最后的节点的时候
        if (index != (path_length - 1)) {
            path[index].node_id = rte->node_ids[index];
            path[index].link_id = rte->link_identifiers[index + 1];
        } else { // 当已经是最后一个节点, 其没有链路标识了
            path[index].node_id = rte->node_ids[index];
            path[index].link_id = 0;
        }
    }
}


static void fill_session_packet_fields(struct SessionHeader *session_header,
                                       struct RoutingTableEntry *rte,
                                       struct SessionID session_id){
    // 1. 进行会话包的 session_id 填充
    fill_session_packet_session_id(session_header, session_id);
    // 2. 进行会话包的 opt_path 填充
    fill_session_packet_path(session_header, rte);
}


struct sk_buff *self_defined_session_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          int getfrag(void *from, char *to, int offset,
                                                      int len, int odd, struct sk_buff *skb),
                                          void *from, int length, int transhdrlen,
                                          struct ipcm_cookie *ipc,
                                          struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr){
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

    // 进行包头大小的获取
    int session_header_size = get_session_header_size(rcr);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, session_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__session_make_skb(sk, fl4, &queue, cork, rcr);
}


struct sk_buff *self_defined__session_make_skb(struct sock *sk,
                                               struct flowi4 *fl4,
                                               struct sk_buff_head *queue,
                                               struct inet_cork *cork,
                                               struct RoutingCalcRes *rcr){
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct SessionHeader *session_header;
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
    session_header = session_hdr(skb);
    session_header->version = SESSION_SETUP_VERSION_NUMBER; // 版本 (字段1)
    session_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    session_header->ttl = ttl; // ttl (字段3)
    session_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    session_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    session_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    session_header->check = 0; // 校验和字段 (字段7)
    session_header->source = rcr->source; // 设置源 (字段8)
    session_header->dest = rcr->user_space_info->destinations[0]; // 设置目的 (字段9)
    session_header->hdr_len = get_session_header_size(rcr); // 设置数据包总长度 (字段10)
    session_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    session_header->path_length = rte->path_length; // 路径长度 (字段13)
    session_header->current_path_index = 0; // 当前的索引 (字段12)
    // ---------------------------------------------------------------------------------------

    // 计算 session_id -> 利用 source / link_identifiers / node_ids / timestamp
    // ---------------------------------------------------------------------------------------
    struct SessionID session_id;
    time64_t current_time_stamp = ktime_get_seconds(); // 进行当前时间的获取
    unsigned char *hash_value = calculate_session_id(pvs->hash_api, rcr, rte,current_time_stamp); // 这里的 session_id 是 20 字节的, 实际只需要 16 字节
    memcpy(&session_id, hash_value, SESSION_ID_LENGTH);
    kfree(hash_value);
    // ---------------------------------------------------------------------------------------

    // 头部后续部分初始化
    // ---------------------------------------------------------------------------------------
    fill_session_packet_fields(session_header, rcr->rtes[0], session_id);
    // ---------------------------------------------------------------------------------------

    // 等待一切就绪后计算 check
    session_setup_send_check(session_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    // 进行 session state 的存储
    // ------------------------------------------------------------------------------
    if (NULL == sk->path_validation_sock_structure) {
        // 进行结构的初始化
        struct PathValidationSockStructure *pvss = init_pvss();
        pvss->sent_first_packet = true;
        pvss->session_id = session_id;
        pvss->timestamp = ktime_get_seconds();
        pvss->session_keys = (unsigned char**) (kmalloc(sizeof(unsigned char *) * rte->path_length, GFP_KERNEL)); // 为指针进行内存的分配
        sk->path_validation_sock_structure = (void *) (pvss);
        int index;
        char secret_value[20];
        for (index = 0; index < rte->path_length; index++) {
            int node_id = rte->node_ids[index];
            // 对 session id 做一次 hmac 的到 key 使用的 key 为 key-%d
            snprintf(secret_value, sizeof(secret_value), "key-%d", node_id);
            // 计算 session_key
            unsigned char *session_key = calculate_hmac(pvs->hmac_api,
                                                        (unsigned char *) (&session_id),
                                                        sizeof(struct SessionID),
                                                        (unsigned char *) (secret_value),
                                                        (int) (strlen(secret_value))); // 注意使用 strlen 的地方, 如果末尾没有 \0 空字符就会很长, 这里是可以使用的, 因为 secret_value 就是字符串
            // 将 session_key 放到指定的位置
            pvss->session_keys[index] = session_key;
        }
    }
    // ------------------------------------------------------------------------------

    out:
    return skb;
}