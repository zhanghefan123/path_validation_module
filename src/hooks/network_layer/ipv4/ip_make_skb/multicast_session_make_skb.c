#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "structure/namespace/namespace.h"
#include "structure/header/multicast_session_header.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "api/test.h"
#include "structure/path_validation_sock_structure.h"

// 1->2 path_length = 1 [link_id=1, node_id=2]

// 1->2->3 path_length = 2 但是实际只需要一跳


/**
 * 进行链路标识的数量的获取
 * @param rcr
 * @return
 */
static int get_link_identifiers_count(struct RoutingCalcRes* rcr){
    // 总的链路标识的数量
    int total_link_identifiers = 0;
    // 开始进行获取
    int index;
    for (index = 0; index < rcr->number_of_routes; index++) {
        total_link_identifiers += rcr->rtes[index]->path_length;
    }
    return total_link_identifiers;
}

/**
 * 进行最长的路径长度的获取
 * @param rcr
 * @return
 */
static int get_max_path_length(struct RoutingCalcRes* rcr) {
    // 最长的路径长度 = 到主节点的路径长度
    int max_length = 0;
    // 到主节点的路径长度
    int to_primary_path_length = rcr->rtes[0]->path_length;
    // 开始进行获取
    int index;
    for (index = 1; index < rcr->number_of_routes; index++) {
        int path_length = to_primary_path_length + rcr->rtes[index]->path_length;
        if (path_length > max_length) {
            max_length = path_length;
        }
    }
    return max_length;
}

static int get_multicast_session_header_size(struct RoutingCalcRes *rcr) {
    // 总的路径数量
    int total_link_identifiers = 0;
    // 记录最长的路径长度
    int max_length = 0;
    // 获取总的路径数量
    total_link_identifiers = get_link_identifiers_count(rcr);
    // 获取最长的路径长度
    max_length = get_max_path_length(rcr);
    // 返回结果
    return sizeof(struct MulticastSessionHeader) +
           sizeof(struct SessionID) +
           total_link_identifiers * sizeof(int) +
           rcr->user_space_info->number_of_destinations * sizeof(int) +
           max_length * sizeof(int);
}

/**
 * 进行 session_id 的计算
 * @return session_id
 */
static unsigned char *calculate_session_id(struct shash_desc *hash_api,
                                           int source,
                                           time64_t current_time) {
    unsigned char *data[2] = {
            (unsigned char *) (&(source)),
            (unsigned char *) (&current_time)
    };
    int lengths[2] = {
            sizeof(int), // source 的字节数
            sizeof(time64_t) // 时间的大小
    };
    unsigned char *session_id = calculate_hash_from_multiple_segments(hash_api, data, lengths, 2);
    return session_id;
}


static void fill_multicast_session_packet_session_id(struct MulticastSessionHeader* session_header, struct SessionID session_id){
    // 获取 session_id 起始 pointer
    unsigned char* session_id_start_pointer = get_multicast_session_setup_session_id_pointer(session_header);
    // 拷贝 session_id 到起始的 pointer
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
}

static void fill_multicast_session_packet_link_identifiers(struct MulticastSessionHeader* session_header, struct RoutingCalcRes* rcr){
    // 索引
    int index;
    // 路径起始字段
    int* link_identifiers = (int*) get_multicast_session_setup_link_identifiers_pointer(session_header);
    // 进行主路径的设置
    struct RoutingTableEntry* rte;
    // 当前应该设置的位置
    int current_position = 0;
    // 进行挨个的设置
    for(index = 0; index < rcr->number_of_routes; index++){
        // 获取当前的路径
        rte = rcr->rtes[index];
        // 进行 link identifiers 的设置
        int inner_index;
        for(inner_index = 0; inner_index < rte->path_length; inner_index++){
            link_identifiers[current_position] = rte->link_identifiers[inner_index];
            current_position++;
        }
    }
}

static void fill_multicast_session_packet_destinations(struct MulticastSessionHeader* session_header, struct RoutingCalcRes* rcr){
    // 获取总的链路标识数量
    int link_identifiers_count = get_link_identifiers_count(rcr);
    // 获取目的地的起始地址
    int* destinations = (int*)get_multicast_session_setup_destination_pointer(session_header, link_identifiers_count);
    // 进行目的地的设置
    int index;
    // index 从 1 开始的原因是, 第一条路由是到主节点的路由
    for(index = 1; index < rcr->user_space_info->number_of_destinations; index++){
        destinations[index-1] = rcr->user_space_info->destinations[index];
    }
}

static void fill_multicast_session_packet_fields(struct MulticastSessionHeader *session_header,
                                                 struct RoutingCalcRes *rcr,
                                                 struct SessionID sessionId) {
    // 1. 进行 session_id 的填充
    fill_multicast_session_packet_session_id(session_header, sessionId);
    // 2. 进行规划的路径的填充
    fill_multicast_session_packet_link_identifiers(session_header, rcr);
    // 3. 进行目的地的填充
    fill_multicast_session_packet_destinations(session_header, rcr);
}

/**
 * 进行所有的 key 的数量的计算
 * @param rcr 路由计算结果
 * @return
 */
static int get_keys_size(struct RoutingCalcRes* rcr){
    // path 1:  1->2->3->4->5
    // path 2:  1->2->3->6->7

    // 修改后的 path 表示方式
    // 到主节点的 path: 1->2->3
    // 其他的 path1: 3->4->5
    // 其他的 path2: 3->6->7

    // 计算所有的 keys

    // [2] -> [3] -> [4]
    // [2] -> [3] -> [6]


    int keys_size = 0;
    int index;
    for(index = 0; index < rcr->number_of_routes; index++){
        if(index == 0){
            keys_size = keys_size + rcr->rtes[index]->path_length;  // 1->2->3
        } else {
            keys_size = keys_size + rcr->rtes[index]->path_length - 1; // ->4->5
        }
    }
    return keys_size;
}

struct sk_buff *self_defined_multicast_session_make_skb(struct sock *sk,
                                                        struct flowi4 *fl4,
                                                        int getfrag(void *from, char *to, int offset,
                                                                    int len, int odd, struct sk_buff *skb),
                                                        void *from, int length, int transhdrlen,
                                                        struct ipcm_cookie *ipc,
                                                        struct inet_cork *cork, unsigned int flags,
                                                        struct RoutingCalcRes *rcr) {
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
    int session_header_size = get_multicast_session_header_size(rcr);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, session_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__multicast_session_make_skb(sk, fl4, &queue, cork, rcr);
}


struct sk_buff *self_defined__multicast_session_make_skb(struct sock *sk,
                                                         struct flowi4 *fl4,
                                                         struct sk_buff_head *queue,
                                                         struct inet_cork *cork,
                                                         struct RoutingCalcRes *rcr) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct MulticastSessionHeader *multicast_session_header;
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

    // 头部基本部分填充
    // ---------------------------------------------------------------------------------------
    multicast_session_header = multicast_session_hdr(skb);
    multicast_session_header->version = MULTICAST_SESSION_SETUP_VERSION_NUMBER; // 版本 (字段1)
    multicast_session_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    multicast_session_header->ttl = ttl; // ttl (字段3)
    multicast_session_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    multicast_session_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    multicast_session_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    multicast_session_header->check = 0; // 校验和字段 (字段7)
    multicast_session_header->source = rcr->source; // 设置源 (字段8)
    multicast_session_header->dest = rcr->user_space_info->destinations[0]; // 设置目的 (字段9)
    multicast_session_header->hdr_len = get_multicast_session_header_size(rcr); // 设置数据包总长度 (字段10)
    multicast_session_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    multicast_session_header->link_identifiers_count = get_link_identifiers_count(rcr); // 路径长度 (字段13) -> 这个字段对于多播来说有不同的含义
    multicast_session_header->destination_count = rcr->user_space_info->number_of_destinations - 1; // 目的节点的数量
    multicast_session_header->current_path_index = 0; // 当前的索引 (字段12)
    // ---------------------------------------------------------------------------------------

    // 计算 session_id -> 利用 source / timestamp 进行计算
    struct SessionID session_id;
    time64_t current_time_stamp = ktime_get_seconds(); // 进行当前时间的获取
    unsigned char *hash_value = calculate_session_id(pvs->hash_api,
                                                     rcr->source,
                                                     current_time_stamp);
    memcpy(&session_id, hash_value, SESSION_ID_LENGTH); // 拷贝到 session_id 中
    kfree(hash_value);

    // 头部后续部分的初始化
    // ---------------------------------------------------------------------------------------
    fill_multicast_session_packet_fields(multicast_session_header, rcr, session_id);
    // ---------------------------------------------------------------------------------------

    // 等待一切准备就绪后计算 check
    multicast_session_setup_send_check(multicast_session_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    // 进行 session state 的存储 (这里先不进行存储了)
    // ----------------------------------------------------------------------------------------
    sk->path_validation_sock_structure = NULL;
    // ----------------------------------------------------------------------------------------

    // 进行 session state 的存储
    // ----------------------------------------------------------------------------------------
    if(NULL == sk->path_validation_sock_structure){
        struct PathValidationSockStructure* pvss = init_pvss();
        pvss->sent_first_packet = true;
        pvss->session_id = session_id;
        pvss->timestamp = ktime_get_seconds();

        // 进行目的节点共享密钥的计算
        pvss->sdk = calculate_shared_destination_key(pvs->hmac_api, &session_id);

        // 计算所有的 keys 总共有多少哥
        int keys_size = get_keys_size(rcr);

        // 为 session_keys 分配内存
        pvss->session_keys = (unsigned char**)(kmalloc(sizeof(unsigned char*) * keys_size, GFP_KERNEL));
        sk->path_validation_sock_structure = (void*)(pvss);
        // 密钥值
        int session_key_position = 0;
        int index;
        for(index = 0; index < rcr->number_of_routes; index++){
            if(index == 0){
                int inner_index;
                struct RoutingTableEntry* rte = rcr->rtes[index];
                for(inner_index = 0; inner_index < rte->path_length; inner_index++){
                    // 节点 id
                    int node_id = rte->node_ids[inner_index];
                    // 计算 session_key
                    unsigned char* session_key = calculate_intermediate_session_key(pvs->hmac_api, &session_id, node_id);
                    // 进行存储
                    pvss->session_keys[session_key_position] = session_key;
                    session_key_position++;
                }
            } else {
                int inner_index;
                struct RoutingTableEntry* rte = rcr->rtes[index];
                for(inner_index = 0; inner_index < rte->path_length - 1; inner_index++){
                    // 节点 id
                    int node_id = rte->node_ids[inner_index];
                    // 计算 session_key
                    unsigned char* session_key = calculate_intermediate_session_key(pvs->hmac_api, &session_id, node_id);
                    pvss->session_keys[session_key_position] = session_key;
                    session_key_position++;
                }
            }
        }

    }
    // ----------------------------------------------------------------------------------------


    out:
    return skb;
}
