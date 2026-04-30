#include "structure/header/multipath_selir_header.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "api/test.h"
#include "structure/routing/hash_based_pvf_cache_table.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

static int get_multipath_selected_path_part_size(struct ArrayBasedMultipathTable* abpt){
    return DIV_ROUND_UP(abpt->number_of_paths, 8);
}


static int get_multipath_selir_header_size(struct MultipathRes *mres, struct PathValidationStructure *pvs) {
    int multipath_selected_path_part_size = get_multipath_selected_path_part_size(pvs->abpt);
    int header_size = sizeof(struct MultipathSELiRHeader) +
                     sizeof(struct DataHash) +
                     sizeof(struct SessionID) +
                     sizeof(struct TimeStamp) +
                     multipath_selected_path_part_size + // 存储实际走过的路径 path
                     sizeof(struct SELiRPvf) + // 存储中间节点 pvf
                     sizeof(struct EncPvf) * mres->number_of_segments +  // 存储目的节点 DVF
                     pvs->bloom_filter->bf_effective_bytes; // PPF
     // printk(KERN_EMERG "header_size = %d\n", header_size);
     return header_size;
}

static void fill_meta_data(struct MultipathSELiRHeader *multipath_selir_header,
                           unsigned char *static_fields_hash,
                           struct SessionID session_id,
                           time64_t timestamp) {
    unsigned char *hash_start_pointer = get_multipath_selir_hash_start_pointer(multipath_selir_header);
    unsigned char *session_id_start_pointer = get_multipath_selir_session_id_start_pointer(multipath_selir_header);
    unsigned char *timestamp_start_pointer = get_multipath_selir_timestamp_start_pointer(multipath_selir_header);
    memcpy(hash_start_pointer, static_fields_hash, HASH_LENGTH);
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
    memcpy(timestamp_start_pointer, &(timestamp), sizeof(time64_t));
}

static unsigned char *
generate_pvf(struct shash_desc *hmac_api, unsigned char *static_fields_hash, char *intermediate_key) {
    unsigned char combination[PVF_LENGTH + HASH_LENGTH] = {0};
    memcpy(combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    combination,
                                                    PVF_LENGTH +
                                                    HASH_LENGTH, // 注意其他的数据接收着也只能拿到 HASH_LENGTH 16 而不是完整的 20 bytes.
                                                    (unsigned char *) intermediate_key,
                                                    (int) strlen(intermediate_key));
    return pvf_hmac_result;
}

static unsigned char *
calculate_next_pvf(struct shash_desc *hmac_api, unsigned char *pvf_start_pointer, unsigned char *static_fields_hash,
                   char *key) {
    unsigned char combination[PVF_LENGTH + HASH_LENGTH] = {0};
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    combination,
                                                    PVF_LENGTH +
                                                    HASH_LENGTH, // 注意其他的数据接收着也只能拿到 HASH_LENGTH 16 而不是完整的 20 bytes.
                                                    (unsigned char *) key,
                                                    (int) strlen(key));
    return pvf_hmac_result;
}


static void fill_validation_fields(struct PathValidationStructure *pvs, struct MultipathRes *mres,
                                   struct MultipathSELiRHeader *multipath_selir_header,
                                   unsigned char *static_fields_hash,
                                   struct shash_desc* hmac_api, struct BloomFilter* bloom_filter, struct HashBasedPvfCacheTable* hbpct) {
    // 进行所有的路径的遍历, 针对每条路径进行 pvf 的构建
    int inner_index;
    // 进行路径链表的遍历
    struct RoutingTableEntry *rte;
    struct list_head *position;
    int index = 0;
    int calculated_macs = 0;
    int count = 0;
    list_for_each(position, mres->segments) {
        rte = list_entry(position, struct RoutingTableEntry, list);
        int node_ids[16] = {0};
        int current_index = 0;
        unsigned char* next_pvf = NULL;
        for (inner_index = 0; inner_index < rte->path_length; inner_index++) {
            if (0 == inner_index) {
                // ------------------------ 生成当前的 path_str ------------------------
                node_ids[current_index++] = rte->node_ids[inner_index];
                // ------------------------ 生成当前的 path_str ------------------------
                // ------------------------ 判断当前的 path_str 是否已经被计算过了  ------------------------
                struct CacheEntry *cache_entry = find_cache_entry_in_hbpct(hbpct, node_ids, current_index);
                // ------------------------ 判断当前的 path_str 是否已经被计算过了  ------------------------
                if (NULL != cache_entry) {
                    // ------------------------ 取出 pvf  -----------------------------
                    next_pvf = cache_entry->pvf_pointer;
                    // memcpy(next_pvf, cache_entry->pvf_cache, PVF_LENGTH);
                    // ------------------------ 取出 pvf  -----------------------------
                } else {
                    // ------------------------ 初始化 pvf  -----------------------------
                    // 进行 key 的获取
                    char intermediate_node_key[20];
                    // 拿到目的节点
                    int intermediate_node = rte->node_ids[inner_index];
                    // 填充 intermediate_node_key
                    snprintf(intermediate_node_key, sizeof(intermediate_node_key), "key-%d", intermediate_node);
                    // 进行 pvf 的获取
                    next_pvf = generate_pvf(hmac_api, static_fields_hash, intermediate_node_key);
                    // ------------------------ 缓存之中没有项进行添加 -----------------------------
                    struct CacheEntry *new_cache_entry = create_cache_entry(node_ids, current_index, next_pvf);
                    add_entry_to_hbpct(hbpct, new_cache_entry);
                    // ------------------------ 缓存之中没有项进行添加 -----------------------------
                    calculated_macs++;
                }
                // ----------------------- push 到 ppf 之中 ------------------------
                push_element_into_bloom_filter(bloom_filter, next_pvf, PVF_LENGTH);
                count += 1;
                // ------------------------ push 到 ppf 之中 ------------------------
            } else if (inner_index != (rte->path_length - 1)) {
                // ------------------------ 生成当前的 path_str ------------------------
                node_ids[current_index++] = rte->node_ids[inner_index];
                // ------------------------ 生成当前的 path_str ------------------------
                // ------------------------ 判断当前的 path_str 是否已经被计算过了  ------------------------
                struct CacheEntry *cache_entry = find_cache_entry_in_hbpct(hbpct, node_ids, current_index);
                // ------------------------ 判断当前的 path_str 是否已经被计算过了  ------------------------
                if (NULL != cache_entry) {
                    // ------------------------ 取出 pvf  -----------------------------
                    next_pvf = cache_entry->pvf_pointer;
                    // ------------------------ 取出 pvf  -----------------------------
                } else {
                    // ------------------------ 基于 pvf 计算 next pvf ------------------------
                    // 进行 key 的获取
                    char intermediate_node_key[20];
                    // 拿到目的节点
                    int intermediate_node = rte->node_ids[inner_index];
                    // 填充 dest_key
                    snprintf(intermediate_node_key, sizeof(intermediate_node_key), "key-%d", intermediate_node);
                    unsigned char *updated_pvf = calculate_next_pvf(hmac_api, next_pvf, static_fields_hash,
                                                                    intermediate_node_key);
                    next_pvf = updated_pvf;
                    // ------------------------ 基于 pvf 计算 next pvf ------------------------
                    // ------------------------ 向缓存之中进行添加 ------------------------
                    struct CacheEntry *new_cache_entry = create_cache_entry(node_ids, current_index, next_pvf);
                    add_entry_to_hbpct(hbpct, new_cache_entry);
                    // ------------------------ 向缓存之中进行添加 ------------------------
                    calculated_macs++;
                }
                // ----------------------- push 到 ppf 之中 ------------------------
                push_element_into_bloom_filter(bloom_filter, next_pvf, PVF_LENGTH);
                count += 1;
                // ------------------------ push 到 ppf 之中 ------------------------
            } else {
                // ------------------------ 生成当前的 path_str ------------------------
                node_ids[current_index++] = rte->node_ids[inner_index];
                // 进行 key 的获取
                char destination_node_key[20];
                // 拿到目的节点
                int destination_node = rte->node_ids[inner_index];
                // 填充 dest_key
                snprintf(destination_node_key, sizeof(destination_node_key), "key-%d", destination_node);
                unsigned char *updated_pvf = calculate_next_pvf(hmac_api, next_pvf, static_fields_hash,
                                                                destination_node_key);
                // 拷贝到 dest pvf 所在的位置
                unsigned char *dest_pvf_start_pointer = get_multipath_selir_ith_dvf_start_pointer(
                        multipath_selir_header, index);
                // 拷贝到数据包的指定位置
                memcpy(dest_pvf_start_pointer, updated_pvf, PVF_LENGTH);
                kfree(updated_pvf);
                calculated_macs++;
            }
        }
        // 代表处理路径数量的增加
        index += 1;
    }

//    printk(KERN_EMERG "bloom filter size: %d\n",count);

    // 打印 pvf 位置
//    LOG_WITH_EDGE("pvf value");
//    print_memory_in_hex(get_multipath_selir_pvf_start_pointer(multipath_selir_header), PVF_LENGTH);
//    LOG_WITH_EDGE("pvf value");
    // printk(KERN_EMERG "calculated macs: %d\n", calculated_macs);


    // 将布隆过滤器进行拷贝
    unsigned char *ppf_start_pointer = get_multipath_selir_ppf_start_pointer(multipath_selir_header,
                                                                             mres->number_of_segments);
    // printk(KERN_EMERG "ppf position = %ld\n", ppf_start_pointer - (unsigned char*)(multipath_selir_header));
    memcpy(ppf_start_pointer, bloom_filter->bitset, bloom_filter->bf_effective_bytes);


    // 在结束之后进行 bloom 过滤器的还原
    // reset_bloom_filter(bloom_filter);
    // 在结束之后还需要进行 hbpct 的重置
//    u64 start_time = ktime_get_real_ns();
    free_hbpct(hbpct);
//    free_hbpct(pvs->hbpct);
//    pvs->hbpct = init_hbpct(100);
//    printk(KERN_EMERG "spend %llu ns\n", ktime_get_real_ns() - start_time);
}

struct sk_buff *self_defined_multipath_selir_make_skb(struct sock *sk,
                                                      struct flowi4 *fl4,
                                                      int getfrag(void *from, char *to, int offset,
                                                                  int len, int odd, struct sk_buff *skb),
                                                      void *from, int length, int transhdrlen,
                                                      struct ipcm_cookie *ipc,
                                                      struct inet_cork *cork, unsigned int flags,
                                                      struct MultipathRes *mres,
                                                      u64* make_skb_time_elapsed,
                                                      u64* enc_time_elapsed) {
    u64 start_time = ktime_get_real_ns();
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

    int multipath_selir_header_size = get_multipath_selir_header_size(mres, pvs);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                         &current->task_frag, getfrag,
                                         from, length, transhdrlen, flags,
                                         mres->ite, multipath_selir_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    struct sk_buff* skb = self_defined__multipath_selir_make_skb(sk, fl4, &queue, cork, mres, length, enc_time_elapsed);
    *make_skb_time_elapsed = ktime_get_real_ns() - start_time;
    return skb;
}

struct sk_buff *self_defined__multipath_selir_make_skb(struct sock *sk,
                                                       struct flowi4 *fl4,
                                                       struct sk_buff_head *queue,
                                                       struct inet_cork *cork,
                                                       struct MultipathRes *mres,
                                                       int app_and_transport_length,
                                                       u64* enc_time_elapsed) {
    int index;
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct MultipathSELiRHeader *multipath_selir_header;
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
    multipath_selir_header = multipath_selir_hdr(skb); // 创建 header
    multipath_selir_header->version = MULTIPATH_SELIR_VERSION_NUMBER; // 版本 (字段1)
    multipath_selir_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    multipath_selir_header->ttl = ttl; // ttl (字段3)
    multipath_selir_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    multipath_selir_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    multipath_selir_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    multipath_selir_header->check = 0; // 校验和字段 (字段7)
    multipath_selir_header->source = pvs->node_id; // 设置源 (字段8)
    multipath_selir_header->hdr_len = get_multipath_selir_header_size(mres, pvs); // 设置数据包头部长度 (字段9)
    multipath_selir_header->tot_len = htons(skb->len); // tot_len 字段 10
    multipath_selir_header->ppf_len = pvs->bloom_filter->bf_effective_bytes; // ppf 长度
    multipath_selir_header->max_path_length = mres->max_path_length; // 所有路径中最大的一条的长度
    multipath_selir_header->selected_paths_part_size = get_multipath_selected_path_part_size(pvs->abpt);
    multipath_selir_header->destination = mres->destination; // 目的节点
    multipath_selir_header->number_of_paths = mres->number_of_segments; // 路径的数量
    multipath_selir_header->current_path_index = 0; // 当前索引
    // ---------------------------------------------------------------------------------------



    // 在源就进行可选路径的填充
    // ---------------------------------------------------------------------------------------
    unsigned char* possible_path_ids_start_pointer = get_possible_path_ids_start_pointer(multipath_selir_header);
    memset(possible_path_ids_start_pointer, 0xff, multipath_selir_header->selected_paths_part_size);
    int useless_bit_index = pvs->abpt->routing_entries_count;
    for (index = useless_bit_index; index < multipath_selir_header->selected_paths_part_size * 8; index++){
        clear_bit(index, (unsigned long*)possible_path_ids_start_pointer);
    }
    if(NULL != mres->selected_mapping){
        for(index = 0; index < multipath_selir_header->selected_paths_part_size; index++){
            possible_path_ids_start_pointer[index] = possible_path_ids_start_pointer[index] & mres->selected_mapping->bit_set[index];
        }
    }
    // ---------------------------------------------------------------------------------------


    u64 start_enc_time = ktime_get_real_ns();
    // 获取 hash_api 和 hmac_api
    struct pv_struct* p = get_cpu_ptr(&validation_api);
//    struct pv_struct p = create_pv_struct(true, true, true, pvs->bloom_filter);
    // 计算哈希值
    unsigned char *static_fields_hash = calculate_multipath_selir_hash(p->hash_api, multipath_selir_header);
    struct SessionID session_id = {
            .first_part = 1,
            .second_part = 1,
    };
    time64_t timestamp = 1;
    // 填充元数据
    fill_meta_data(multipath_selir_header, static_fields_hash, session_id, timestamp);
    // 进行验证字段的填充
    fill_validation_fields(pvs, mres, multipath_selir_header, static_fields_hash, p->hmac_api, p->bloom_filter, p->hbpct);
    put_cpu_ptr(p);
//    free_pv_struct(&p);
    *enc_time_elapsed = ktime_get_real_ns() - start_enc_time;

    // 填充完字段之后打印一下 payload
//    unsigned char *payload =
//            (unsigned char *) multipath_selir_header + multipath_selir_header->hdr_len + sizeof(struct udphdr);
    // print_memory_in_hex(payload, app_and_transport_length - sizeof(struct udphdr));

    // ---------------------------------------------------------------------------------------

    // 等待一切就绪之后计算 校验和
    multipath_selir_send_check(multipath_selir_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
}
