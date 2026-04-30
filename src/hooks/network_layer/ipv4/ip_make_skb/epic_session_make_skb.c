#include "structure/header/epic_session_header.h"
#include "structure/header/epic_fields_length.h"
#include "structure/routing/routing_calc_res.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "structure/namespace/namespace.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include <linux/time.h>

// host1->as1->as2->host2 我们传入的路径是3跳, 这里实际上是 2 跳, 只考虑 as1 和 as2
// get_epic_session_hops 获取实际的 hop identifiers 的数量
static int get_epic_session_hops(struct RoutingTableEntry* rte){
    return rte->path_length - 1;
}

// get_epic_session_hops 获取实际的 epic_session_header 的大小
static int get_epic_session_header_size(struct RoutingCalcRes* rcr){
    // 拿到路由条目
    struct RoutingTableEntry *rte = rcr->rtes[0];
    // 拿到路径
    int epic_session_hops = get_epic_session_hops(rte);
    // 返回结果
    return  sizeof(struct EpicSessionHeader) +
            PATH_TIMESTAMP_LENGTH +
            epic_session_hops * sizeof(struct EpicHopIdentifier) +
            epic_session_hops * sizeof(struct EpicHopAuthenticator);
}

// 填充 timestamp
static void fill_epic_path_timestamp(struct EpicSessionHeader* epic_session_header){
    // 进行时间的设置
    u64* timestamp_pointer  = (u64*)get_epic_session_setup_timestamp_pointer(epic_session_header);
    *timestamp_pointer = ktime_get_real_seconds();
}


/**
 * EPIC 采用不一样的路径存储方式
 *
 * host1  (LID1) --> <-- (LID2) AS1 (LID3) -->  <-- (LID4) AS2 (LID5) --> host2
 *
   beacon 逐步更新之后, host2  收到的路径
   path[0] node_id = AS1 | link_identifier = LID3 | incoming link_identifier = LID2
   path[1] node_id = AS2 | link_identifier = LID5 | incoming link_identifier = LID4

   host2 向 host1 发送时使用的路径 (进行反向遍历即可)
   path[0] node_id = AS1 | link_identifier = LID3 | incoming link_identifier = LID2
   path[1] node_id = AS2 | link_identifier = LID5 | incoming link_identifier = LID4
 * @param epic_session_header
 * @param rte
 */
static void fill_epic_session_packet_path(struct EpicSessionHeader *epic_session_header, struct RoutingTableEntry *rte) {
    // 索引
    int path_index;
    // 路径起始字段
    struct EpicHopIdentifier *hop_identifiers = get_epic_session_setup_hop_identifiers_start_pointer(epic_session_header);
    // 路径长度
    int path_length = rte->path_length - 1;
    // 进行路径的设置
    for (path_index = 0; path_index < path_length; path_index++) {
        hop_identifiers[path_index].node_id = rte->node_ids[path_index];
        hop_identifiers[path_index].link_id = rte->link_identifiers[path_index+1]; // 设置了 link_id [1-2]
        hop_identifiers[path_index].incoming_link_id = 0;
    }
}

static void fill_epic_session_packet_fields(struct EpicSessionHeader* epic_session_header, struct RoutingTableEntry* rte) {
    // 初始化路径时间戳
    fill_epic_path_timestamp(epic_session_header);
    // 初始化路径字段
    fill_epic_session_packet_path(epic_session_header, rte);
    // 不用初始化验证字段 (后续会进行初始化)
}

struct sk_buff* self_defined_epic_session_make_skb(struct sock *sk,
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
    err = self_defined_xx_setup_cork(sk, cork, ipc);
    if (err) {
        return ERR_PTR(err);
    }

    // 进行包头大小的获取
    int session_header_size = get_epic_session_header_size(rcr);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr->ite, session_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__epic_session_make_skb(sk, fl4, &queue, cork, rcr);
}

struct sk_buff *self_defined__epic_session_make_skb(struct sock *sk,
                                                    struct flowi4 *fl4,
                                                    struct sk_buff_head *queue,
                                                    struct inet_cork *cork,
                                                    struct RoutingCalcRes *rcr){
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct EpicSessionHeader *epic_session_header;
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
    epic_session_header = epic_session_hdr(skb);
    epic_session_header->version = EPIC_SESSION_VERSION_NUMBER; // 版本 (字段1)
    epic_session_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    epic_session_header->ttl = ttl; // ttl (字段3)
    epic_session_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    epic_session_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    epic_session_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    epic_session_header->check = 0; // 校验和字段 (字段7)
    epic_session_header->source = rcr->source; // 设置源 (字段8)
    epic_session_header->dest = rcr->user_space_info->destinations[0]; // 设置目的 (字段9)
    epic_session_header->hdr_len = get_epic_session_header_size(rcr); // 设置数据包总长度 (字段10)
    epic_session_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    epic_session_header->length_of_path = rte->path_length; // 路径长度 (字段13)
    epic_session_header->current_path_index = 0; // 当前的索引 (字段12)
    // ---------------------------------------------------------------------------------------


    // 头部后续部分初始化
    // ---------------------------------------------------------------------------------------
    fill_epic_session_packet_fields(epic_session_header, rcr->rtes[0]);
    // ---------------------------------------------------------------------------------------

    // 等待一切就绪后计算 check
    epic_session_setup_send_check(epic_session_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
}