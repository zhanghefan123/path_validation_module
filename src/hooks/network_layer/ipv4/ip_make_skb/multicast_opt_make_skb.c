#include "structure/header/multicast_opt_header.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/path_validation_sock_structure.h"
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"

static int get_multicast_opt_header_size(struct RoutingCalcRes *rcr) {
    // 所有的 OPV 的数量
    int number_of_opvs = 0;
    // 拿到其他的路径长度
    int index;
    for (index = 0; index < rcr->number_of_routes; index++) {
        struct RoutingTableEntry *rte = rcr->rtes[index];
        number_of_opvs += rte->path_length;
    }
    // 进行总长度的计算
    return sizeof(struct MulticastOptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp)
           + sizeof(struct OptPvf)
           + sizeof(struct OptOpv) * number_of_opvs;
}

static void fill_meta_data(struct MulticastOptHeader *multicast_opt_header, unsigned char *static_fields_hash,
                           struct SessionID session_id,
                           time64_t timestamp) {
    unsigned char *hash_start_pointer = get_multicast_opt_hash_start_pointer(multicast_opt_header);
    unsigned char *session_id_start_pointer = get_multicast_opt_session_id_start_pointer(multicast_opt_header);
    unsigned char *timestamp_start_pointer = get_multicast_opt_timestamp_start_pointer(multicast_opt_header);
    memcpy(hash_start_pointer, static_fields_hash, HASH_LENGTH);
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
    memcpy(timestamp_start_pointer, &(timestamp), sizeof(time64_t));
}

/**
 * 进行 pvf 字段的填充
 * @param hmac_api hmac api
 * @param pvf_start_pointer pvf 起始指针
 * @return 计算好的 pvf0
 */
static void initialize_pvf(unsigned char *pvf_start_pointer) {
    memset(pvf_start_pointer, 0, PVF_LENGTH); // 全部为0
}


//       opv1 --> opv2 --> opv3
// R1     R2       R3       R4  为 R2 R3 R4 分别进行计算, 发送的 pvf 是空的
static void initialize_opvs(struct shash_desc *hmac_api, struct OptOpv *opvs, unsigned char *static_fields_hash,
                            struct RoutingCalcRes *rcr, struct PathValidationSockStructure *pvss) {
    int session_key_count = 0;
    // 计算第一个节点的 pvf
    unsigned char *next_pvf = kmalloc(PVF_LENGTH, GFP_KERNEL);
    memset(next_pvf, 0, PVF_LENGTH);

    // 进行后续节点的 opv 和 pvf 的计算
    unsigned char opv_combination[PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t)];

    // 进行主路由的所有节点的遍历
    struct RoutingTableEntry* main_route = rcr->rtes[0];
    int primary_path_length = main_route->path_length;
    int index;
    int opv_count = 0;
    // a ---> (L1) ---> b ---> (L2) ---> c
    for(index = 0; index < primary_path_length; index++){
        // 拿到 session key
        unsigned char* session_key = pvss->session_keys[session_key_count++];
        // 进行前驱节点的 id 的获取
        int previous_node_id;
        if(index == 0){
            previous_node_id = main_route->source_id;
        } else {
            previous_node_id = main_route->node_ids[index -1];
        }
        // 进行 opv_combination 的填充
        memcpy(opv_combination, next_pvf, PVF_LENGTH);
        memcpy(opv_combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
        memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH, &(previous_node_id), sizeof(int));
        memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), &(pvss->timestamp), sizeof(time64_t));

        // 基于旧的 pvf 进行 opv 的计算
        unsigned char* opv_result = calculate_hmac(hmac_api,
                                                    opv_combination,
                                                    PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                    session_key,
                                                    HMAC_OUTPUT_LENGTH);

        // 将计算出来的 opv 放到指定的位置之后进行释放
        unsigned char* opv_position = (unsigned char*)(opvs + opv_count);
        memcpy(opv_position, opv_result, OPV_LENGTH);
        kfree(opv_result);
        opv_count += 1;

        // 基于旧的 pvf 进行新的 pvf 的计算
        unsigned char* new_pvf = calculate_hmac(hmac_api,
                                                next_pvf,
                                                PVF_LENGTH,
                                                session_key,
                                                HMAC_OUTPUT_LENGTH);

        // 进行旧的 pvf 的释放
        if(NULL != next_pvf){
            kfree(next_pvf);
            next_pvf = NULL;
        }
        next_pvf = new_pvf;
    }

    unsigned char* final_pvf_of_primary_route = kmalloc(PVF_LENGTH, GFP_KERNEL);
    memcpy(final_pvf_of_primary_route, next_pvf, PVF_LENGTH);

    // 进行其他节点的所有的路由的遍历
    for(index = 1; index < rcr->number_of_routes; index++) {
        // 拿到其他路由
        struct RoutingTableEntry *rte = rcr->rtes[index];
        int inner_index;
        for(inner_index = 0; inner_index < rte->path_length; inner_index++){
            if(inner_index == 0){
                unsigned char* session_key = pvss->session_keys[session_key_count++];
                memcpy(opv_combination, final_pvf_of_primary_route, PVF_LENGTH);
                memcpy(opv_combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
                memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH, &(rte->source_id), sizeof(int));
                memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), &(pvss->timestamp), sizeof(time64_t));

                unsigned char* hmac_result = calculate_hmac(hmac_api,
                                                            opv_combination,
                                                            PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                            session_key,
                                                            HMAC_OUTPUT_LENGTH);
                unsigned char* opv_position = (unsigned char*)(opvs + opv_count);
                memcpy(opv_position, hmac_result, OPV_LENGTH);
                kfree(hmac_result);
                opv_count += 1;

                // 基于旧的 pvf 进行新的 pvf 的计算
                unsigned char* new_pvf = calculate_hmac(hmac_api,
                                                        final_pvf_of_primary_route,
                                                        PVF_LENGTH,
                                                        session_key,
                                                        HMAC_OUTPUT_LENGTH);


                // 更新 next_pvf
                if (next_pvf != NULL){
                    kfree(next_pvf);
                    next_pvf = NULL;
                }
                next_pvf = new_pvf;
            } else if(inner_index != (rte->path_length - 1)){
                // 拿到 session_key
                unsigned char* session_key =  pvss->session_keys[session_key_count++];

                // 进行拼接
                memcpy(opv_combination, next_pvf, PVF_LENGTH);
                memcpy(opv_combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
                memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH, &(rte->node_ids[inner_index - 1]), sizeof(int));
                memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), &(pvss->timestamp), sizeof(time64_t));

                // 进行 hmac 的计算
                unsigned char* opv_result = calculate_hmac(hmac_api,
                                                            opv_combination,
                                                            PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                            session_key,
                                                            HMAC_OUTPUT_LENGTH);
                // 将计算出来的 opv 放到指定的位置之后进行释放
                unsigned char* opv_position = (unsigned char*)(opvs + opv_count);
                memcpy(opv_position, opv_result, OPV_LENGTH);
                kfree(opv_result);
                opv_count += 1;

                // 基于旧的 pvf 进行新的 pvf 的计算
                unsigned char* new_pvf = calculate_hmac(hmac_api,
                                                        next_pvf,
                                                        PVF_LENGTH,
                                                        session_key,
                                                        HMAC_OUTPUT_LENGTH);

                // 更新 next_pvf
                if (next_pvf != NULL){
                    kfree(next_pvf);
                    next_pvf = NULL;
                }
                next_pvf = new_pvf;
            } else {
                // 拿到 session_key
//                unsigned char* session_key =  pvss->session_keys[session_key_count++];
                // 进行拼接
                memcpy(opv_combination, next_pvf, PVF_LENGTH);
                memcpy(opv_combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
                memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH, &(rte->node_ids[inner_index - 1]), sizeof(int));
                memcpy(opv_combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), &(pvss->timestamp), sizeof(time64_t));
                // 进行 hmac 的计算
                unsigned char* opv_result = calculate_hmac(hmac_api,
                                                            opv_combination,
                                                            PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                           (unsigned char *) "sdk",
                                                           strlen("sdk"));
                // 将计算出来的 opv 放到指定的位置之后进行释放
                unsigned char* opv_position = (unsigned char*)(opvs + opv_count);
                memcpy(opv_position, opv_result, OPV_LENGTH);
                kfree(opv_result);
                opv_count += 1;
                // 进行释放
                if(next_pvf != NULL){
                    kfree(next_pvf);
                    next_pvf = NULL;
                }
            }
        }
    }

    if(NULL != static_fields_hash){
        kfree(static_fields_hash);
    }

    if(NULL != final_pvf_of_primary_route){
        kfree(final_pvf_of_primary_route);
    }

    if (NULL != next_pvf){
        kfree(next_pvf);
    }
}

struct sk_buff* self_defined_multicast_opt_make_skb(struct sock *sk,
                                                    struct flowi4 *fl4,
                                                    int getfrag(void *from, char *to, int offset,
                                                                int len, int odd, struct sk_buff *skb),
                                                    void *from, int length, int transhdrlen,
                                                    struct ipcm_cookie *ipc,
                                                    struct inet_cork *cork, unsigned int flags,
                                                    struct RoutingCalcRes *rcr,
                                                    u64* make_skb_time_elapsed){
    u64 start_make_skb_time = ktime_get_real_ns();
    struct sk_buff_head queue;
    int err;
    struct net *current_ns = sock_net(sk);
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

    int multicast_opt_header_size = get_multicast_opt_header_size(rcr);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr->ite, multicast_opt_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    struct sk_buff* result = self_defined__multicast_opt_make_skb(sk, fl4, &queue, cork, rcr, length);
    *make_skb_time_elapsed = ktime_get_real_ns() - start_make_skb_time;
    return result;
}


struct sk_buff* self_defined__multicast_opt_make_skb(struct sock* sk, struct flowi4 *fl4,
                                                     struct sk_buff_head *queue, struct inet_cork *cork,
                                                     struct RoutingCalcRes *rcr, int app_and_transport_length){
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct MulticastOptHeader *multicast_opt_header;
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
    multicast_opt_header = multicast_opt_hdr(skb); // 创建 header
    multicast_opt_header->version = MULTICAST_OPT_VERSION_NUMBER; // 版本 (字段1)
    multicast_opt_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    multicast_opt_header->ttl = ttl; // ttl (字段3)
    multicast_opt_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    multicast_opt_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    multicast_opt_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    multicast_opt_header->check = 0; // 校验和字段 (字段7)
    multicast_opt_header->source = rcr->source; // 设置源 (字段8)
    multicast_opt_header->hdr_len = get_multicast_opt_header_size(rcr); // 设置数据包头部长度 (字段9)
    multicast_opt_header->tot_len = htons(skb->len); // tot_len 字段 10
    multicast_opt_header->dest_len = (rcr->user_space_info->number_of_destinations - 1); // 目的数量, 这里进行减1的原因是多播之中的主节点也被认为是目的节点之中的一个

    // 1. 拿到 pvss
    struct PathValidationSockStructure* pvss = (struct PathValidationSockStructure*)(sk->path_validation_sock_structure);

    // 2. 拿到 hash hmac_api
    struct pv_struct* p = get_cpu_ptr(&validation_api);

    // 3. 进行哈希的计算
    unsigned char* static_fields_hash = calculate_multicast_opt_hash(p->hash_api, multicast_opt_header);

    // 4. 元数据的填充
    fill_meta_data(multicast_opt_header, static_fields_hash, pvss->session_id, pvss->timestamp);

    // 5. 进行 pvf 字段的初始化
    initialize_pvf(get_multicast_opt_pvf_start_pointer(multicast_opt_header));

    // 6. 进行 opv 字段的初始化
    initialize_opvs(p->hmac_api, get_multicast_opt_opv_start_pointer(multicast_opt_header), static_fields_hash,
                    rcr, pvss);

    // 7. 进行 per cpu ptr 的放回
    put_cpu_ptr(p);

    // 8. 进行 payload 的获取
//    unsigned char* payload = (unsigned char*)(multicast_opt_header) + multicast_opt_header->hdr_len + sizeof(struct udphdr);
//    print_memory_in_hex(payload, app_and_transport_length - sizeof(struct udphdr));

    // 9. 等待一切就绪计算校验和
    multicast_opt_send_check(multicast_opt_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;

}