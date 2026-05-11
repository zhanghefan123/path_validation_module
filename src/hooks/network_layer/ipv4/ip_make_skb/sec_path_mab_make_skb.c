#include "api/test.h"
#include "types/sec_path_mab_types.h"
#include "structure/routing/table_common.h"
#include "structure/namespace/namespace.h"
#include "structure/header/sec_path_mab_header.h"
#include "structure/path_validation_sock_structure.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"


/**
 * 进行 data_hash, session_id 以及 timestamp 的填充
 * @param sec_path_mab_header opt 首部
 * @param static_fields_hash 静态字段的哈希
 * @param session_id 会话 id
 * @param timestamp 时间戳
 */
static void
fill_meta_data(struct SecPathMabHeader *mab_header, unsigned char *static_fields_hash, u64 timestamp) {
    struct SecPathMabMetadata *metadata = get_sec_path_mab_metadata(mab_header);
    memcpy(&(metadata->datahash), static_fields_hash, HASH_LENGTH);
    memcpy(&(metadata->timestamp), &(timestamp), sizeof(time64_t));
}

/**
 * initializ the current pvf and return the initialized pvf result
 * @param hmac_api hmac api
 * @param pvf_start_pointer  the pointer to the start of the pvf field in the header
 * @param static_fields_hash   hash
 * @param dest_session_key  destination session key
 * @return
 */
static unsigned char *initialize_mab_pvf(struct shash_desc *hmac_api,
                                         unsigned char *static_fields_hash,
                                         unsigned char *pvf_start_pointer,
                                         int destination_id) {

    char destination_session_key[20];
    snprintf(destination_session_key, sizeof(destination_session_key), "key-%d", destination_id);
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    static_fields_hash,
                                                    HASH_LENGTH, // 注意其他的数据接收着也只能拿到 HASH_LENGTH 16 而不是完整的 20 bytes.
                                                    (unsigned char *) (destination_session_key),
                                                    (int) (strlen(destination_session_key)));
    memcpy(pvf_start_pointer, pvf_hmac_result, PVF_LENGTH);
    return pvf_hmac_result;
}

static int initialize_mab_hvfs(struct PathValidationStructure *pvs,
                               struct shash_desc *hash_api,
                               struct shash_desc *hmac_api,
                               unsigned char *first_pvf_result,
                               unsigned char *static_fields_hash,
                               struct MabHvf *hvf_start_pointer,
                               struct SecPathMabRoute *sec_path_mab_route,
                               int sampling_router_index,
                               u64 current_time) {
    int final_result = 0;
    // 1. initialize ack authentication
    unsigned char *ack_authentication = (unsigned char *) kmalloc(sizeof(unsigned char) * ACK_AUTHENTICATION_LENGTH,
                                                                  GFP_ATOMIC);
    memset(ack_authentication, 0, ACK_AUTHENTICATION_LENGTH);
    // 2. session key
    char session_key[20] = {0};
    // 3. store pvfs 这里进行+1保障的是目的节点还会更新一个 pvf
    int number_of_pvfs = sec_path_mab_route->number_of_sample_nodes + 1;
    unsigned char **pvfs = (unsigned char **) (kmalloc(
            sizeof(unsigned char *) * (number_of_pvfs), GFP_ATOMIC));
    pvfs[0] = first_pvf_result;
    // 4. generate pvfs S->A->B->C->D
    int index;
    for (index = 0; index < sec_path_mab_route->number_of_sample_nodes; index++) {
        // retrieve intermediate session key
        snprintf(session_key, sizeof(session_key), "key-%d", sec_path_mab_route->sample_node_ids[index]);
        // calculate the updated pvf with the session key
        unsigned char *new_pvf_result = calculate_hmac(hmac_api,
                                                       pvfs[index],
                                                       PVF_LENGTH,
                                                       (unsigned char *) (session_key),
                                                       (int) (strlen(session_key)));
        pvfs[index + 1] = new_pvf_result;
    }
    // 5. initialize hvfs
    unsigned char **hvfs = (unsigned char **) (kmalloc(
            sizeof(unsigned char *) * sec_path_mab_route->number_of_sample_nodes, GFP_ATOMIC));
    memset(hvfs, 0, sizeof(unsigned char *) * sec_path_mab_route->number_of_sample_nodes);

    struct StatisticsForSingleEpoch *sfse = NULL;
    if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH){
        sfse = find_sfse_in_hbale(pvs->hbale,pvs->sec_path_mab_settings->current_epoch);
    } else {
        sfse = find_sfse_in_hbale(pvs->hbale, pvs->sec_path_mab_settings->current_retrieve_epoch);
    }

    // 6. set hvfs in a reverse order (number_of_sample_nodes = 5) index 最大为 4
    for (index = 0; index < sec_path_mab_route->number_of_sample_nodes; index++) {
        // 6.1 get session key
        int current_hvf_index = sec_path_mab_route->number_of_sample_nodes - index - 1;
        snprintf(session_key, sizeof(session_key), "key-%d", sec_path_mab_route->sample_node_ids[current_hvf_index]);
        // 6.2 get the combination
        int current_offset = 0;
        unsigned char combination[200] = {0};
        // 6.2.1 combine the pvf
        memcpy(combination, pvfs[current_hvf_index], PVF_LENGTH);
        current_offset += PVF_LENGTH;
        // 6.2.2 combine the hvfs
        int hvf_start_index = sec_path_mab_route->number_of_sample_nodes - index;
        int hvf_copy_count = index;
        if (0 != hvf_copy_count) {
            unsigned char *start_pointer = (unsigned char *) (&(hvf_start_pointer[hvf_start_index]));
            memcpy(combination + current_offset, start_pointer, sizeof(struct MabHvf) * hvf_copy_count);
            current_offset += sizeof(struct MabHvf) * hvf_copy_count;
        }
        // 6.2.3 combine the static fields hash
        memcpy(combination + current_offset, static_fields_hash, HASH_LENGTH);
        current_offset += HASH_LENGTH;
        // 6.2.4 combine the timestamp field
        memcpy(combination + current_offset, &current_time, sizeof(struct TimeStamp));
        current_offset += sizeof(struct TimeStamp);

        // 6.2.5 calculate the hvf
        unsigned char *hvf = calculate_hmac(hmac_api,
                                            combination,
                                            current_offset,
                                            (unsigned char *) session_key,
                                            (int) (strlen(session_key)));

        if (sampling_router_index == current_hvf_index) {
            // after the computation of hvfs and pvfs we start to perform sampling operation
            // -----------------------------------------------------------------------------------------------------------------------------------------
            snprintf(session_key, sizeof(session_key), "key-%d",
                     sec_path_mab_route->sample_node_ids[sampling_router_index]);
            int length_of_session_key = (int) strlen(session_key);
            unsigned char sample_identifier_combination[HASH_OUTPUT_LENGTH + length_of_session_key];
            memcpy(sample_identifier_combination, static_fields_hash, HASH_OUTPUT_LENGTH);
            memcpy(sample_identifier_combination + HASH_OUTPUT_LENGTH, session_key, length_of_session_key);
            // calculate sample identifier
            unsigned char *sample_identifier = calculate_hash(hash_api,
                                                              sample_identifier_combination,
                                                              HASH_OUTPUT_LENGTH + length_of_session_key);

            // perform xor operation
            memory_xor(hvf, sample_identifier, sizeof(struct MabHvf));

            // get ack authentication field
            memory_xor(ack_authentication, sample_identifier, ACK_AUTHENTICATION_LENGTH);
            memory_xor(ack_authentication, pvfs[sampling_router_index + 1],
                       PVF_LENGTH); // 当 sampling_router_index == 4 的时候, sampling_router_index+1 == 6

            // put ack authentication field in the alfe
            struct HashBasedAckCacheTableForSingleEpoch *hbase = NULL;
            if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH){
                hbase = find_hbase_in_hbace(pvs->hbace,pvs->sec_path_mab_settings->current_epoch);
            } else {
                hbase = find_hbase_in_hbace(pvs->hbace, pvs->sec_path_mab_settings->current_retrieve_epoch);
            }

            if (NULL == hbase) {
                final_result = -EINVAL;
                printk(KERN_EMERG "hbase is NULL\n");

                // free hvf
                if (NULL != hvf) {
                    kfree(hvf);
                }

                // free sample identifier
                if (NULL != sample_identifier) {
                    kfree(sample_identifier);
                }

                goto drop_zone;
            } else {
                u64 current_timestamp = ktime_get_us();
                update_sfse_expected_ack_and_timestamp(sfse, current_timestamp, sampling_router_index);
                struct AckCacheEntry *ack_cache_entry = create_ack_cache_entry(sampling_router_index,
                                                                               ack_authentication,
                                                                               current_timestamp);

                int result = add_entry_to_hbase(hbase, ack_cache_entry);
                increment_sfse_sampling_packets(sfse);
                if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH){
                    struct SampleSequence* sample_sequence = pvs->sec_path_mab_settings->selected_route->sample_sequence;
                    if(1 == sample_sequence->current_index){
                        sfse->start_sending_timestamp = current_timestamp;
                    }
                    if((sample_sequence->sequence_length) == sample_sequence->current_index){
                        sfse->end_sending_timestamp = current_timestamp;
                    }
                } else {
                    if(1 == get_sfse_sampling_packets(sfse)) {
                        sfse->start_sending_timestamp = current_timestamp;
                    }
                }

                if (result != ADD_SUCCESS) {
                    final_result = -EINVAL;
                    printk(KERN_EMERG "add entry to hbase failed\n");

                    // free hvf
                    if (NULL != hvf) {
                        kfree(hvf);
                    }

                    // free sample identifier
                    if (NULL != sample_identifier) {
                        kfree(sample_identifier);
                    }

                    goto drop_zone;
                }
            }

            // free sample identifier
            if (NULL != sample_identifier) {
                kfree(sample_identifier);
            }
            // -----------------------------------------------------------------------------------------------------------------------------------------
        }

        // set the hvf in the right position
        hvfs[current_hvf_index] = hvf;

        // put the hvf in the correct position
        memcpy(&(hvf_start_pointer[current_hvf_index]), hvf, sizeof(struct MabHvf));
    }

    if(sampling_router_index == sec_path_mab_route->number_of_sample_nodes){
        increment_sfse_unsampling_packets(sfse);
    }

drop_zone:

    // free ack authentication
    if(NULL != ack_authentication){
        kfree(ack_authentication);
    }

    // release the memory of pvfs
    if (NULL != pvfs) {
        int pvf_index;
        for (pvf_index = 0; pvf_index < (sec_path_mab_route->number_of_sample_nodes + 1); pvf_index++) {
            if (NULL != pvfs[pvf_index]) {
                kfree(pvfs[pvf_index]);
            }
        }
        kfree(pvfs);
    }

    // release the memory of hvfs
    if (NULL != hvfs) {
        int hvf_index;
        for (hvf_index = 0; hvf_index < sec_path_mab_route->number_of_sample_nodes; hvf_index++) {
            if (NULL != hvfs[hvf_index]) {
                kfree(hvfs[hvf_index]);
            }
        }
        kfree(hvfs);
    }

    return final_result;
}

// S->R1->R2->R3->D (3 hop identifiers, 4 HVFs)
static void fill_path_part(struct SecPathMabHeader *sec_path_mab_header, struct SecPathMabRoute *sec_path_mab_route) {
    // 1. get the path part
    struct SecPathMabPathPart *path_part = get_sec_path_mab_path_part(sec_path_mab_header);
    // 2. set the corresponding link identifiers
    int index;
    // note that length_of_path equals to the number_of_link_identifiers
    for (index = 0; index < sec_path_mab_route->number_of_link_identifiers; index++) {
        path_part->hop_identifiers[index].link_id = sec_path_mab_route->link_identifiers[index];
    }
}

static int fill_validation_part(struct PathValidationStructure *pvs,
                                struct SecPathMabHeader *sec_path_mab_header,
                                struct SecPathMabRoute *sec_path_mab_route,
                                int sampling_router_index) {
    // 1. get the validation part
    struct SecPathMabValidationPart *validation_part = get_sec_path_mab_validation_part(sec_path_mab_header,
                                                                                        sec_path_mab_route->number_of_link_identifiers);

    // 2. get current time
    u64 current_time = ktime_get_ns();
    struct TimeStamp time_stamp;
    *((u64 *) (time_stamp.data)) = current_time;
    // 3. 禁止下半部中断
    local_bh_disable();
    // 4. 获取 per-cpu 变量
    struct pv_struct *p = get_cpu_ptr(&validation_api);
    // 5. calculate hash
    unsigned char *static_fields_hash = calculate_sec_path_mab_hash(p->hash_api, sec_path_mab_header, &time_stamp);
    // 6. fill the path validation header's [metadata] part
    fill_meta_data(sec_path_mab_header, static_fields_hash, current_time);
    // 7. initialize MabPvf
    unsigned char *pvf_hmac_result = initialize_mab_pvf(p->hmac_api,
                                                        static_fields_hash,
                                                        (unsigned char *) &(validation_part->pvf),
                                                        sec_path_mab_route->destination_id);

    // 8. initialize MabHvfs
    int result = initialize_mab_hvfs(pvs, p->hash_api, p->hmac_api, pvf_hmac_result, static_fields_hash,
                                     validation_part->hvfs, sec_path_mab_route, sampling_router_index, current_time);
    // 9. 释放 per-cpu 变量
    put_cpu_ptr(&validation_api);
    // 10. 开启中断
    local_bh_enable();
    // 11. 如果结果不对的话就直接返回错误
    if (result != 0) {
        printk(KERN_EMERG "initialize mab hvfs failed\n");
    }
    // 12. 释放哈希结果
    if (NULL != static_fields_hash) {
        kfree(static_fields_hash);
    }

    return result;
}

struct sk_buff *self_defined_sec_path_make_skb(struct sock *sk,
                                               struct flowi4 *fl4,
                                               int getfrag(void *from, char *to, int offset,
                                                           int len, int odd, struct sk_buff *skb),
                                               void *from, int length, int transhdrlen,
                                               struct ipcm_cookie *ipc,
                                               struct inet_cork *cork, unsigned int flags,
                                               struct PathValidationStructure *pvs) {

    // 存储每个包的信息
    struct PerPacketInfo* per_packet_info = (struct PerPacketInfo*)(kmalloc(sizeof(struct PerPacketInfo), GFP_KERNEL));
    spin_lock_bh(&pvs->sec_path_mab_settings->lock);
    per_packet_info->best_path_id = pvs->sec_path_mab_settings->best_path_id;
    spin_unlock_bh(&pvs->sec_path_mab_settings->lock);
    per_packet_info->selected_path_id = pvs->sec_path_mab_settings->selected_route->path_id;
    xa_store(&per_packet_info_array, pvs->sec_path_mab_settings->current_packet_index++, per_packet_info, GFP_KERNEL);


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

    // 进行包头的大小的获取, 不同类型的包不一样
    int sec_path_mab_header_size = get_sec_path_mab_header_size(pvs->sec_path_mab_settings->selected_route->number_of_link_identifiers,
                                                                pvs->sec_path_mab_settings->selected_route->number_of_sample_nodes);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       pvs->sec_path_mab_settings->selected_route->ite, sec_path_mab_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    struct sk_buff *result = self_defined__sec_path_make_skb(sk, fl4, &queue, cork,
            pvs->sec_path_mab_settings->selected_route, length);
    return result;
}

struct sk_buff *self_defined__sec_path_make_skb(struct sock *sk,
                                                struct flowi4 *fl4,
                                                struct sk_buff_head *queue,
                                                struct inet_cork *cork,
                                                struct SecPathMabRoute *sec_path_mab_route,
                                                int app_and_transport_length) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct SecPathMabHeader *sec_path_mab_header;
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
    sec_path_mab_header = sec_path_mab_hdr(skb);
    sec_path_mab_header->version = SEC_PATH_MAB_VERSION_NUMBER; // 版本 (字段1)
    sec_path_mab_header->identifier = pvs->sec_path_mab_settings->current_packet_identifier++;
    if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH){
        sec_path_mab_header->epoch = pvs->sec_path_mab_settings->current_epoch; // epoch (字段2)
    } else {
        sec_path_mab_header->epoch = pvs->sec_path_mab_settings->current_retrieve_epoch;
    }
    sec_path_mab_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    sec_path_mab_header->ttl = ttl; // ttl (字段3)
    sec_path_mab_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    sec_path_mab_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    sec_path_mab_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    sec_path_mab_header->check = 0; // 校验和字段 (字段7)
    sec_path_mab_header->source = sec_path_mab_route->source_id; // 设置源 (字段8)
    sec_path_mab_header->dest = sec_path_mab_route->destination_id; // 设置目的 (字段9)
    sec_path_mab_header->hdr_len = get_sec_path_mab_header_size(sec_path_mab_route->number_of_link_identifiers,
                                                                sec_path_mab_route->number_of_sample_nodes); // 设置数据包总长度 (字段10)
    sec_path_mab_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    sec_path_mab_header->length_of_path = sec_path_mab_route->number_of_link_identifiers;
    sec_path_mab_header->current_path_index = 0; // 当前的索引 (字段12)
    // ---------------------------------------------------------------------------------------

    // 拿到 hash_api 和 hmac_api
    // struct pv_struct p_node = create_pv_struct(true, true, false, NULL);
    // struct pv_struct *p = &p_node;

    // 选择哪个节点进行采样 (根据确定好的 current_index 进行采样即可)
    int sampling_router_index;
    if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH){
        struct SampleSequence* sample_sequence= pvs->sec_path_mab_settings->selected_route->sample_sequence;
        sampling_router_index = sample_sequence->actual_sequence[sample_sequence->current_index++];
    } else {
        bool send_sample_packets = get_send_sample_packets(pvs->sec_path_mab_settings);
        if(send_sample_packets) {
            sampling_router_index = uniform_sample_index(sec_path_mab_route->number_of_sample_nodes);
        } else {
            // printk(KERN_EMERG "not sample any nodes\n");
            sampling_router_index = sec_path_mab_route->number_of_sample_nodes;
        }
    }


    // 发送一个 batch 数据包的延迟肯定要大于端到端的往返延迟, 进行发送包的速率的统计, 用速率乘上最后那个节点的往返延迟来进行 batch_size 的设置,
    // 相当于让沿途的所有节点都充斥着这些包, 等待一个往返延迟, 所有的这些包都能收到了, 然后可以进行模型权重的更新了

    // 路径部分初始化
    fill_path_part(sec_path_mab_header, sec_path_mab_route);

    // 校验部分初始化
    int result = fill_validation_part(pvs, sec_path_mab_header,
                                      sec_path_mab_route,
                                      sampling_router_index);

    // 进行 cpu_ptr 的释放
    //    put_cpu_ptr(p);
    // free_pv_struct(p);

    // 如果结果不对的话就直接返回错误
    if (result != 0) {
        kfree_skb(skb);
        return NULL;
    }

    // 进行 payload 的获取
    //    unsigned char *payload =
    //            (unsigned char *) (sec_path_mab_header) + sec_path_mab_header->hdr_len + sizeof(struct udphdr);
    //    printk(KERN_EMERG "-------------------- payload --------------------\n");
    //    print_memory_in_hex(payload, app_and_transport_length - sizeof(struct udphdr));
    //    printk(KERN_EMERG "-------------------- payload --------------------\n");

    // 等待一切就绪后计算 check
    sec_path_mab_send_check(sec_path_mab_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
}