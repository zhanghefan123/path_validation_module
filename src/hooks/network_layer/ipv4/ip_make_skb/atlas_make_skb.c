#include <net/ip.h>
#include <structure/routing/routing_calc_res.h>
#include <structure/header/atlas_header.h>
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "structure/header/atlas_header.h"
#include "structure/routing/multipath_res.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/path_validation_sock_structure.h"
#include "structure/header/atlas_segment.h"
#include "structure/header/atlas_header_list.h"
#include "structure/header/atlas_validation_field.h"
#include "structure/header/atlas_tag.h"


/**
 * 进行 data_hash, session_id 以及 timestamp 的填充
 * @param atlas_header atlas 首部
 * @param static_fields_hash 静态字段的哈希
 * @param session_id 会话 id
 * @param timestamp 时间戳
 */
static void
fill_meta_data(struct AtlasHeader *atlas_header, unsigned char *static_fields_hash, struct SessionID session_id,
               time64_t timestamp) {
    unsigned char *hash_start_pointer = get_other_atlas_hash_start_pointer(atlas_header);
    unsigned char *session_id_start_pointer = get_other_atlas_session_id_start_pointer(atlas_header);
    unsigned char *timestamp_start_pointer = get_other_atlas_timestamp_start_pointer(atlas_header);
    memcpy(hash_start_pointer, static_fields_hash, HASH_LENGTH);
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
    memcpy(timestamp_start_pointer, &(timestamp), sizeof(time64_t));
}

/**
 * 获取 atlas 首部的大小 [standard_header | datahash | sessionid | timestamp | [start tag] | pvf | opv... | [end tag]]
 * @param mres
 * @return
 */
static int get_atlas_header_size(struct MultipathRes *mres) {
    // 1. 取出 pvs->segment_list
    struct AtlasSegment *atlas_segment;
    struct list_head *position;
    // 2. 首部基本的大小
    int atlas_header_size =
            sizeof(struct AtlasHeader) + sizeof(struct DataHash) + sizeof(struct SessionID) + sizeof(struct TimeStamp);
    // 3. 根据 segments 的数量判断需要的大小
    list_for_each(position, (mres->segments)) {
        atlas_segment = list_entry(position, struct AtlasSegment, list);
        atlas_header_size += ATLAS_TAG_SIZE;
        atlas_header_size += TYPE_IDENTIFIER_LENGTH + PVF_LENGTH;
        atlas_header_size += (TYPE_IDENTIFIER_LENGTH + OPV_LENGTH) * (atlas_segment->length - 1);
        atlas_header_size += ATLAS_END_TAG_SIZE;
    }
    // 4. 返回整个首部的大小
    return atlas_header_size;
}


struct sk_buff *self_defined_atlas_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            int getfrag(void *from, char *to, int offset,
                                                        int len, int odd, struct sk_buff *skb),
                                            void *from, int length, int transhdrlen,
                                            struct ipcm_cookie *ipc,
                                            struct inet_cork *cork, unsigned int flags,
                                            struct MultipathRes *mres,
                                            u64* make_skb_time_elapsed,
                                            u64* turn_time_elapsed,
                                            u64* integrate_time_elapsed) {
    u64 start_time = ktime_get_real_ns();
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
    int atlas_header_size = get_atlas_header_size(mres);
    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       mres->ite, atlas_header_size);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    struct sk_buff* maked_skb = self_defined__atlas_make_skb(sk, fl4, &queue, cork, mres, length, turn_time_elapsed, integrate_time_elapsed);
    *make_skb_time_elapsed = ktime_get_real_ns() - start_time;
    return maked_skb;
}

// 根据 segments_list 生成 header lists
static struct HeaderConstructionResult turn_segment_lists_into_header_lists(struct MultipathRes *mres,
                                                                            unsigned char *static_fields_hash, struct shash_desc* hmac_api) {
    // 0. 最终结果
    struct HeaderConstructionResult result = {};
    // 1. create and init all_header_lists
    struct list_head *all_header_lists = kmalloc(sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(all_header_lists);
    // 2. create atlas segment and position for latter traverse
    struct AtlasSegment *atlas_segment;
    struct list_head *position;
    // 3. traverse to generate and find max depth
    int max_depth = -1;
    int mac_total = 0;
    list_for_each(position, mres->segments) {
        // retrive the current atlas segment
        atlas_segment = list_entry(position, struct AtlasSegment, list);
        if(NULL == atlas_segment){
            LOG_WITH_PREFIX("atlas segment == NULL");
            continue;
        }
        // generate header_list from segment
        struct HeaderList *header_list = create_header_list_from_segment(atlas_segment, static_fields_hash, hmac_api, &mac_total);
        // update max depth
        if (atlas_segment->depth > max_depth) {
            max_depth = atlas_segment->depth;
        }
        // add header_list to all_header_lists
        INIT_LIST_HEAD(&(header_list->list));
        list_add_tail(&(header_list->list), all_header_lists);
    }
//    printk(KERN_EMERG "mac total = %d\n", mac_total);

    result.all_header_list = all_header_lists;
    result.max_depth = max_depth;
    return result;
}


static void __fill_data_packet_fields(struct AtlasHeader *atlas_header, struct list_head *all_header_list) {
    if (list_empty(all_header_list)) {
        printk(KERN_EMERG "all_header_list is empty error\n");
        return; // 或者 BUG/WARN
    }
    // 拿到元数据的长度
    int meta_data_length = sizeof(struct AtlasHeader) + HASH_LENGTH + SESSION_ID_LENGTH + TIMESTAMP_LENGTH;
    // 只要拿到第一个 header list (因为经过 integrate 之后只有一个 header_list)
    struct HeaderList *header_list = list_entry(all_header_list->next, struct HeaderList, list);
    // 遍历第一个 header list 之中的 validation field
    struct list_head *position;
    struct ValidationField *validation_field;
    // 将当前指针位置更新到 validation_part
    unsigned char* original_pointer = (unsigned char *) (atlas_header);
    unsigned char *validation_part_pointer = (unsigned char *) (atlas_header) + meta_data_length;
    // 进行 validation_field_list 的遍历
    list_for_each(position, (header_list->validation_field_list)) {
        // 拿到当前的 validation field
        validation_field = list_entry(position, struct ValidationField, list);
        if ((VALIDATION_FIELD_TYPE_TAG == validation_field->type) ||
            (VALIDATION_FIELD_TYPE_END_TAG == validation_field->type)) {  // tag 或者 end_tag
            if((validation_part_pointer + ATLAS_TAG_SIZE - original_pointer) > atlas_header->hdr_len){
                printk(KERN_EMERG "error happens: break here 1\n"); // 这里是避免写出数据包的内存空间
                break;
            }
            memcpy(validation_part_pointer, validation_field, ATLAS_TAG_SIZE); // 拷贝前两个字节正好是 type 和 segment
            validation_part_pointer += ATLAS_TAG_SIZE;
        } else {  // PVF 或者 OPV
            if((validation_part_pointer + PVF_LENGTH - original_pointer) > atlas_header->hdr_len){
                printk(KERN_EMERG "error happens: break here 2\n");  // 这里是避免写出数据包的内存空间
                break;
            }
            *(validation_part_pointer) = validation_field->type;
            validation_part_pointer += TYPE_IDENTIFIER_LENGTH;
            memcpy(validation_part_pointer, validation_field->validation_field, PVF_LENGTH);
            validation_part_pointer += PVF_LENGTH; // PVF_LENGTH == OPV_LENGTH
        }
    }
}


/**
 * 进行 packet_fields 的填充
 * @param atlas_header
 * @param mres
 */
static void fill_data_packet_fields(struct AtlasHeader *atlas_header, struct MultipathRes *mres, struct SessionID session_id,
                                    struct shash_desc* hash_api, struct shash_desc* hmac_api, u64*turn_time_elapsed, u64* integrate_time_elapsed) {

    // 2. 首先计算哈希
    unsigned char *static_fields_hash = calculate_atlas_hash(hash_api, atlas_header);
    // 3. 进行基础的字段的填充
    fill_meta_data(atlas_header, static_fields_hash, session_id, 1);
    // 3. 进行 header_lists 的构建
    u64 start_turn_time = ktime_get_real_ns();
    struct HeaderConstructionResult result = turn_segment_lists_into_header_lists(mres, static_fields_hash, hmac_api);
    *turn_time_elapsed = ktime_get_real_ns() - start_turn_time;
    // 4. 打印最大深度
    // 5. 将这些 header_lists 进行 integrate
    u64 start_integrate_time = ktime_get_real_ns();
    integrate(result.all_header_list, result.max_depth);
    *integrate_time_elapsed = ktime_get_real_ns() - start_integrate_time;
    // 6. 打印经过 integrate 之后的 all_header_list
//    print_all_header_lists(result.all_header_list); // 这里进行打印会报错
    // 7. 根据 all_header_list 进行填充
    __fill_data_packet_fields(atlas_header, result.all_header_list);
    // 8. 在源节点也可能发生需要释放的需求
    remove_all_header_list(result.all_header_list);
}

struct sk_buff *self_defined__atlas_make_skb(struct sock *sk,
                                             struct flowi4 *fl4,
                                             struct sk_buff_head *queue,
                                             struct inet_cork *cork,
                                             struct MultipathRes *mres,
                                             int app_and_transport_length,
                                             u64* turn_time_elapsed,
                                             u64* integrate_time_elapsed) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct AtlasHeader *atlas_header;
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
    atlas_header = atlas_hdr(skb); // 创建 header (总共9个字段 + 剩余的补充部分)
    atlas_header->version = ATLAS_VERSION_NUMBER; // 版本 (字段1)
    atlas_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    atlas_header->ttl = ttl; // ttl (字段3)
    atlas_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    atlas_header->frag_off = htons(IP_DF);; // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    atlas_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    atlas_header->check = 0; // 校验和字段 (字段7)
    atlas_header->source = pvs->node_id; // 设置源 (字段8)
    atlas_header->dest = mres->destination; // 设置目的 (字段9)
    atlas_header->hdr_len = get_atlas_header_size(mres); // 设置数据包总长度 (字段10)
    atlas_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    atlas_header->length_of_path = mres->number_of_segments; // 设置长度 (字段12) 长度代表的是 segment 的数量
    atlas_header->current_path_index = 0; // 当前的索引 (字段13)
    // ---------------------------------------------------------------------------------------

    int meta_data_length = sizeof(struct AtlasHeader) + HASH_LENGTH + TIMESTAMP_LENGTH + SESSION_ID_LENGTH;

    // 头部后续部分初始化
    // ---------------------------------------------------------------------------------------
    // 直接从 sock 之中所保存的 path_validation_sock_structure 之中拿到 session_id
    struct SessionID session_id = {
            .first_part = 1,
            .second_part = 1,
    };
    // ---------------------------------------------------------------------------------------

    // 获取 hash_api 和 hmac_api
    // ---------------------------------------------------------------------------------------
    struct pv_struct p = create_pv_struct(true, true, false, NULL);
//    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // ---------------------------------------------------------------------------------------

    // 进行其他字段的填充
    fill_data_packet_fields(atlas_header, mres, session_id, p.hash_api, p.hmac_api, turn_time_elapsed, integrate_time_elapsed);

    // 进行释放
    free_pv_struct(&p);
//    put_cpu_ptr(p);

    // 进行填充完字段之后拿到 payload 的指针并进行 payload 部分的打印
//    printk(KERN_EMERG "HEADER SIZE = %d\n", atlas_header->hdr_len);
    // unsigned char *payload = (unsigned char *) atlas_header + atlas_header->hdr_len + sizeof(struct udphdr);
    // print_memory_in_hex(payload, app_and_transport_length - sizeof(struct udphdr));

    // 等待一切就绪后计算 check
    atlas_send_check(atlas_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);
    out:
    return skb;
}