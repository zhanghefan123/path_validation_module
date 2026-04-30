#include "api/test.h"
#include "structure/header/epic_header.h"
#include "structure/namespace/namespace.h"
#include "structure/header/epic_fields_length.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"


struct sk_buff *self_defined_epic_make_skb(struct sock *sk,
                                           struct flowi4 *fl4,
                                           int getfrag(void *from, char *to, int offset,
                                                       int len, int odd, struct sk_buff *skb),
                                           void *from, int length, int transhdrlen,
                                           struct ipcm_cookie *ipc,
                                           struct inet_cork *cork, unsigned int flags, struct EpicSessionTableEntry *este,
                                           u64 *make_skb_time_elapsed,
                                           u64 *enc_time_elapsed) {
    u64 start_make_skb_time = ktime_get_real_ns();

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
    int epic_header_size = get_epic_header_size(este->meta.epic_session_hops);
    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       este->meta.ite, epic_header_size);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    struct sk_buff* result =  self_defined__epic_make_skb(sk, fl4, &queue, cork, este, enc_time_elapsed, length);

    *make_skb_time_elapsed = ktime_get_real_ns() - start_make_skb_time;

    return result;
}


/**
 *
 *
   epic 在 beacon 实际建立的过程之中存储的就是 (link_id: | node_id: | incoming link id: )
 * 进行 epic 字段的填充
 *  1----[link_id=1]--->2----[link_id=3]--->3
    1,3,2,1,2,3,3
    (source) (dest) (path_length) (link_identifier) (node_id) (link_identifier) (node_id)
    其实我们真正需要记录的就是
    [node_id=2, link_id=3] [node_id=3, link_id=None]
   功能: 拷贝 epic 路径
   @param epic_header epic 头部
 * @param current_ns 当前的网络命名空间
 * @param este 通过 beacon 建立的路由表项ee
 */
static void fill_epic_path(struct EpicHeader *epic_header, struct EpicSessionTableEntry *este) {
    u32 source = este->meta.source;
    u32 destination = este->meta.destination;
    struct EpicPathPart *path_part = get_epic_path_part_start_pointer(epic_header);
    // 进行 meta data 的填充
    path_part->path_part_meta.src = source;
    path_part->path_part_meta.dest = destination;
    path_part->path_part_meta.path_time_stamp = este->meta.path_timestamp;
//    printk(KERN_EMERG "fill epic path timestamp: %llu\n", path_part->path_part_meta.path_time_stamp);
    // 进行 hop_identifiers 的填充
    unsigned char *este_hop_identifiers_start_pointer = (unsigned char*)(este->hop_identifiers);
    memcpy(path_part->hop_identifiers, este_hop_identifiers_start_pointer, sizeof(struct EpicHopIdentifier) * este->meta.epic_session_hops);
//    print_memory_in_hex((unsigned char*)path_part, get_epic_header_path_part_size(este->meta.epic_session_hops));
}


// 进行验证字段的填充
static void fill_epic_validation(struct EpicHeader *epic_header, struct EpicSessionTableEntry *este,
                                  struct PathValidationStructure *pvs, int udp_app_len, struct shash_desc* hmac_api, struct shash_desc* hash_api) {
    // 0. 计算完 hash 直接释放, 作为对没有考虑 payload 的惩罚
    unsigned char* static_fields_hash = calculate_epic_hash(hash_api, epic_header);
    kfree(static_fields_hash);

    // 0. 字段初始化
    u64 current_timestamp = ktime_get_seconds();

    // 8 + 8 + 8 + 8 + (v1,2,3,4)
    // 1. 定义 concatenation for vsd 并填充前序部分 pkttimestamp || [PATH_TIMESTAMP || SRC || DEST || (H1)...(Hi)] 和 Payload 没有进行填充
    // --------------------------------------------------------------------------------------------------
    int payload_length = udp_app_len - sizeof(struct udphdr);
//    int concatenation_for_vsd_length = PACKET_TIMESTAMP_LENGTH + sizeof(struct PathPartMeta) + sizeof(struct EpicHopIdentifier) * este->meta.epic_session_hops + HOP_VALIDATION_FIELD_LENGTH * este->meta.epic_session_hops + payload_length;
    int concatenation_for_vsd_length = PACKET_TIMESTAMP_LENGTH + sizeof(struct PathPartMeta) + sizeof(struct EpicHopIdentifier) * este->meta.epic_session_hops + HOP_VALIDATION_FIELD_LENGTH * este->meta.epic_session_hops;
    unsigned char* concatenation_for_vsd = (unsigned char*)kmalloc(concatenation_for_vsd_length, GFP_KERNEL);

    memcpy(concatenation_for_vsd, &(current_timestamp), PACKET_TIMESTAMP_LENGTH);
    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH, &(este->meta.path_timestamp), PATH_TIMESTAMP_LENGTH);
    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + PATH_TIMESTAMP_LENGTH, &(este->meta.source), ADDRESS_LENGTH);
    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + PATH_TIMESTAMP_LENGTH + ADDRESS_LENGTH, &(este->meta.destination), ADDRESS_LENGTH);
    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + PATH_TIMESTAMP_LENGTH + ADDRESS_LENGTH + ADDRESS_LENGTH, este->hop_identifiers, sizeof(struct EpicHopIdentifier) * este->meta.epic_session_hops);
    // --------------------------------------------------------------------------------------------------

    // 2. 获取验证部分
    struct EpicValidationPart* validation_part = (get_epic_validation_part_start_pointer(epic_header));
    // 设置数据包时间戳
    validation_part->path_validation_meta.packet_timestamp = current_timestamp;
    // 进行验证字段的填充
    char kis[20];
    // 进行逆序
    int index;
    for(index = 0; index < este->meta.epic_session_hops; index++){
        // 构建 k-as-src
        snprintf(kis, sizeof(kis), "key-%d-%d", este->hop_identifiers[index].node_id, pvs->node_id);
        // 构建 segment identifier
        unsigned char segment_identifier[SEGMENT_IDENTIFIER_LENGTH];
        memcpy(segment_identifier, (unsigned char*)(&(este->hop_authenticators[index])), SEGMENT_IDENTIFIER_LENGTH);
        // 构建 concatenation
        unsigned char concatenation[PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH + HOP_AUTHENTICATOR_LENGTH];
        // 设置 concatenation
        memcpy(concatenation, &(validation_part->path_validation_meta.packet_timestamp), PACKET_TIMESTAMP_LENGTH);
        memcpy(concatenation + PACKET_TIMESTAMP_LENGTH, &(este->meta.source), ADDRESS_LENGTH);
        memcpy(concatenation + PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH, &(este->hop_authenticators[index]),  HOP_AUTHENTICATOR_LENGTH);

        // 进行 MAC 的计算
        unsigned char* hop_validation_field = calculate_hmac(hmac_api,
                       concatenation,
                       PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH + HOP_AUTHENTICATOR_LENGTH,
                       (unsigned char*)kis,
                       (int)(strlen(kis)));

//        LOG_WITH_PREFIX("DEST CONCATENATION_FOR_HOP_VALIDATION");
//        printk(KERN_EMERG "%s\n", kis);
//        print_memory_in_hex(concatenation, PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH + HOP_AUTHENTICATOR_LENGTH);
//        print_memory_in_hex(hop_validation_field, HOP_VALIDATION_FIELD_LENGTH * 2);
//        LOG_WITH_PREFIX("DEST CONCATENATION_FOR_HOP_VALIDATION");

        // 将 segment identifier 放到对应的位置
        memcpy((unsigned char*)&(validation_part->validationHops[index].segment_identifier), segment_identifier , SEGMENT_IDENTIFIER_LENGTH);
        // hop_validation_field first part 放到对应的位置
        memcpy((unsigned char*)&(validation_part->validationHops[index].hop_validation_field), hop_validation_field , HOP_VALIDATION_FIELD_LENGTH);
        // hop_validation_field second part 放到对应的位置
//        unsigned char* second_part_destination = concatenation_for_vsd + PATH_TIMESTAMP_LENGTH + ADDRESS_LENGTH + ADDRESS_LENGTH + index * HOP_VALIDATION_FIELD_LENGTH;
        // 8 + 3 * 8 = 32
        // 32 + 6 * 3  = 50
        unsigned char* second_part_destination = concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + PATH_TIMESTAMP_LENGTH + ADDRESS_LENGTH + ADDRESS_LENGTH + sizeof(struct EpicHopIdentifier) * este->meta.epic_session_hops + index * HOP_VALIDATION_FIELD_LENGTH;
        memcpy(second_part_destination, hop_validation_field + HOP_VALIDATION_FIELD_LENGTH, HOP_VALIDATION_FIELD_LENGTH);
        // 进行 hop_validation_field  的释放
        kfree(hop_validation_field);
        // 进行结果的打印
    }

    // 将 segment identifiers 以及 | part1 hop validation fields 以及  | part2 hop validation fields 进行打印


    // 进行 payload 的拷贝
//    unsigned char* payload = (unsigned char*)(epic_header) + get_epic_header_size(este->meta.epic_session_hops) + sizeof(struct udphdr);
//    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + PATH_TIMESTAMP_LENGTH + ADDRESS_LENGTH + ADDRESS_LENGTH + sizeof(struct EpicHopIdentifier) * este->meta.epic_session_hops + HOP_VALIDATION_FIELD_LENGTH * este->meta.epic_session_hops, payload, udp_app_len - sizeof(struct udphdr));

//    LOG_WITH_EDGE("SOURCE CONCATENATION_FOR_VSD");
//    print_memory_in_hex(concatenation_for_vsd, concatenation_for_vsd_length);
//    printk(KERN_EMERG "concatenation for vsd length = %d\n", concatenation_for_vsd_length);
//    LOG_WITH_EDGE("SOURCE CONCATENATION_FOR_VSD");


    // 进行 ksd 的准别
    snprintf(kis, sizeof(kis), "key-%llu-%llu", este->meta.source, este->meta.destination);

    // 进行实际的计算
    unsigned char* validation_vsd = calculate_hmac(hmac_api,
                                                   concatenation_for_vsd,
                                                   concatenation_for_vsd_length,
                                                   (unsigned char*)kis,
                                                   (int)(strlen(kis)));

    // 将 validation_vsd 进行拷贝
    memcpy(&(validation_part->path_validation_meta.destination_validation_field), validation_vsd, DESTINATION_VALIDATION_LENGTH);

//    for(index =0 ;index < este->meta.epic_session_hops; index++){
        // -------------------------------- validation fields print --------------------------------
//        char output[1024];
//        snprintf(output, sizeof(output), "validation field %d", index);
//        LOG_WITH_EDGE(output);
//        print_memory_in_hex(hop_validation_field, HOP_VALIDATION_FIELD_LENGTH * 2);
//        print_memory_in_hex((unsigned char*)&(validation_part->validationHops[index].segment_identifier), SEGMENT_IDENTIFIER_LENGTH);
//        print_memory_in_hex((unsigned char*)&(validation_part->validationHops[index].hop_validation_field), HOP_VALIDATION_FIELD_LENGTH);
//        print_memory_in_hex(second_part_destination, HOP_VALIDATION_FIELD_LENGTH);
//        LOG_WITH_EDGE(output);
        // -------------------------------- validation fields print --------------------------------
//    }

    // 释放内存
    kfree(validation_vsd);
    kfree(concatenation_for_vsd);
}

struct sk_buff *self_defined__epic_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            struct sk_buff_head *queue,
                                            struct inet_cork *cork,
                                            struct EpicSessionTableEntry *este,
                                            u64 *enc_time_elapsed,
                                            int app_udp_len) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct EpicHeader *epic_header;
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

    // 头部基本部分填充
    // ---------------------------------------------------------------------------------------
    epic_header = epic_hdr(skb); // 创建 header (总共9个字段 + 剩余的补充部分)
    epic_header->version = EPIC_VERSION_NUMBER; // 版本 (字段1)
    epic_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    epic_header->ttl = ttl; // ttl (字段3)
    epic_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    epic_header->frag_off = htons(IP_DF);; // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    epic_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    epic_header->check = 0; // 校验和字段 (字段7)
    epic_header->source = este->meta.source; // 设置源 (字段8)
    epic_header->dest = este->meta.destination; // 设置目的 (字段9)
    epic_header->hdr_len = get_epic_header_size(este->meta.epic_session_hops); // 设置数据包总长度 (字段10)
    epic_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    epic_header->length_of_path = este->meta.epic_session_hops+1; // 设置长度 (字段12)
    epic_header->current_path_index = 0; // 当前的索引 (字段13)
    // ---------------------------------------------------------------------------------------

    u64 start_enc_time = ktime_get_real_ns();
    // 获取 hash_api 和 hmac_api
    // ---------------------------------------------------------------------------------------
    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // ---------------------------------------------------------------------------------------


    // 头部后续部分初始化
    // ---------------------------------------------------------------------------------------
    fill_epic_path(epic_header, este); // 填充路径部分
    // ---------------------------------------------------------------------------------------

    // 头部验证字段初始化
    // ---------------------------------------------------------------------------------------
    fill_epic_validation(epic_header, este, pvs, app_udp_len, p->hmac_api, p->hash_api); // 填充验证字段部分
    // ---------------------------------------------------------------------------------------

    put_cpu_ptr(p);
    *enc_time_elapsed = ktime_get_real_ns() - start_enc_time;

//    struct EpicPathPart *path_part = get_epic_path_part_start_pointer(epic_header);
//    print_memory_in_hex((unsigned char*)path_part, get_epic_header_path_part_size(epic_header->length_of_path-1) + get_epic_header_validation_part_size(epic_header->length_of_path-1));


    // 等待一切就绪后计算 check
    epic_send_check(epic_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);
    out:
    return skb;
}