#include "tools/tools.h"
#include "structure/routing/hash_based_ack_list_table.h"
#include "structure/routing/table_common.h"

/**
 * HashBasedAckListForEachEpoch 初始化
 * @param bucket_count
 * @return
 */
struct HashBasedAckListForEachEpoch *init_hbale(int bucket_count) {
    struct HashBasedAckListForEachEpoch *hbale = (struct HashBasedAckListForEachEpoch *) (kmalloc(
            sizeof(struct HashBasedAckListForEachEpoch), GFP_KERNEL));

    // 准备初始化一个哈希表
    hbale->bucket_count = bucket_count;
    struct hlist_head *head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * bucket_count, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
        return NULL;
    }
    // 初始化表头
    int index;
    for (index = 0; index < bucket_count; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    hbale->bucket_count = bucket_count;
    hbale->bucket_array = head_pointer_list;

    // 初始化自旋锁
    spin_lock_init(&hbale->lock);

    return hbale;
}

/**
 * HashBasedAckListForEachEpoch 释放
 * @param hbale
 */
void free_hbale(struct HashBasedAckListForEachEpoch *hbale) {
    if (NULL == hbale) {
        LOG_WITH_PREFIX("cannot free hbale since hbale is NULL");
        return;
    }
    int index;
    // 释放 bucket_array
    struct hlist_head *hash_bucket = NULL;
    struct StatisticsForSingleEpoch *sfse = NULL;
    struct hlist_node *next;

    for (index = 0; index < hbale->bucket_count; index++) {
        hash_bucket = &(hbale->bucket_array[index]);
        // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
        if (NULL == hash_bucket) {
            LOG_WITH_PREFIX("hash bucket is null, cannot be free");
            continue;
        }
        // 进行加锁
        spin_lock_bh(&(hbale->lock));
        hlist_for_each_entry_safe(sfse, next, hash_bucket, pointer) {
            if (NULL != sfse) {
                free_sfse_with_pointer(sfse);
            }
        }
        // 进行释放锁
        spin_unlock_bh(&(hbale->lock));
    }

    // 进行 bucket array 的释放
    kfree(hbale->bucket_array);
    // 进行 hbale 的释放
    kfree(hbale);
}

//struct StatisticsForSingleEpoch* init_sfse_for_dynamic_batch(int number_of_sample_nodes, int epoch_id){
//    struct StatisticsForSingleEpoch *sfse = (struct StatisticsForSingleEpoch *) (kmalloc(
//            sizeof(struct StatisticsForSingleEpoch), GFP_KERNEL));
//    sfse->timeout_timestamp = ktime_get_us();
//    sfse->epoch = epoch_id;
//    sfse->number_of_sample_nodes = number_of_sample_nodes;
//    sfse->start_sending_timestamp = 0;
//    sfse->expected_acks = (int *) (kmalloc(sizeof(int) * sfse->number_of_sample_nodes, GFP_KERNEL));
//    sfse->received_acks = (int *) (kmalloc(sizeof(int) * sfse->number_of_sample_nodes, GFP_KERNEL));
//    sfse->batch_size = -1;
//    sfse->number_of_sent_packets = 0;
//    sfse->refuse_retrieve_once = false;
//    sfse->rtt_estimators = (struct RttEstimator *) (kmalloc(sizeof(struct RttEstimator) * sfse->number_of_sample_nodes,
//                                                            GFP_KERNEL));
//    int index;
//    for (index = 0; index < sfse->number_of_sample_nodes; index++) {
//        int single_hop_us = 20000;
//        init_rtt_estimator(&(sfse->rtt_estimators[index]), 10000, single_hop_us * (index+2)); // 初始化 RTT 估计器，最小 RTO 50ms，最大 RTO 120ms
//    }
//    if (NULL != sfse->expected_acks) {
//        memset(sfse->expected_acks, 0, sizeof(int) * sfse->number_of_sample_nodes);
//    }
//    if (NULL != sfse->received_acks) {
//        memset(sfse->received_acks, 0, sizeof(int) * sfse->number_of_sample_nodes);
//    }
//
//    // 初始化自旋锁
//    spin_lock_init(&sfse->lock);
//    return sfse;
//}

/**
 * 进行 ArrayBasedExpAckTable 的初始化
 * @param number_of_entries
 * @return
 */
struct StatisticsForSingleEpoch *init_sfse(int number_of_sample_nodes, int epoch_id, int batch_size) {
    struct StatisticsForSingleEpoch *sfse = (struct StatisticsForSingleEpoch *) (kmalloc(
            sizeof(struct StatisticsForSingleEpoch), GFP_KERNEL));
    sfse->timeout_timestamp = ktime_get_us();
    sfse->epoch = epoch_id;
    sfse->number_of_sample_nodes = number_of_sample_nodes;
    sfse->start_sending_timestamp = 0;
    sfse->expected_acks = (int *) (kmalloc(sizeof(int) * sfse->number_of_sample_nodes, GFP_KERNEL));
    sfse->received_acks = (int *) (kmalloc(sizeof(int) * sfse->number_of_sample_nodes, GFP_KERNEL));
    sfse->batch_size = batch_size;
    sfse->number_of_sampling_packets = 0;
    sfse->number_of_unsampling_packets = 0;
    sfse->already_collected_acks = false;
    sfse->rtt_estimators = (struct RttEstimator *) (kmalloc(sizeof(struct RttEstimator) * sfse->number_of_sample_nodes,GFP_KERNEL));
    int index;
    for (index = 0; index < sfse->number_of_sample_nodes; index++) {
        int single_hop_us = 80000;
        init_rtt_estimator(&(sfse->rtt_estimators[index]), 10000, single_hop_us * (index+2)); // 初始化 RTT 估计器，最小 RTO 50ms，最大 RTO 120ms
    }
    if (NULL != sfse->expected_acks) {
        memset(sfse->expected_acks, 0, sizeof(int) * sfse->number_of_sample_nodes);
    }
    if (NULL != sfse->received_acks) {
        memset(sfse->received_acks, 0, sizeof(int) * sfse->number_of_sample_nodes);
    }

    // 初始化自旋锁
    spin_lock_init(&sfse->lock);
    return sfse;
}

/**
 * 进行 ArrayBasedExpAckTable 的释放
 * @param abeat 要释放的 array_based_exp_ack_table
 */
void free_sfse(struct StatisticsForSingleEpoch *sfse) {
    if (NULL != sfse) {
        if (NULL != sfse->expected_acks) {
            kfree(sfse->expected_acks);
        }
        if (NULL != sfse->received_acks) {
            kfree(sfse->received_acks);
        }
        if (NULL != sfse->rtt_estimators) {
            kfree(sfse->rtt_estimators);
        }
        kfree(sfse);
    }
}

void free_sfse_with_pointer(struct StatisticsForSingleEpoch *sfse) {
    if (NULL != sfse) {
        hlist_del(&(sfse->pointer));
        free_sfse(sfse);
    }
}

/**
 * 根据 epoch_id 获取 HashBasedAckListForEachEpoch 中对应的 bucket
 * @param hbale
 * @param epoch_id
 * @return
 */
struct hlist_head *get_bucket_in_hbale(struct HashBasedAckListForEachEpoch *hbale, int epoch_id) {
    // 获取 hash truncate
    u64 hash_truncate = epoch_id % hbale->bucket_count;
    // 找到对应的桶的索引
    u64 index_of_bucket = hash_truncate % hbale->bucket_count;
    // 进行桶的返回
    return &(hbale->bucket_array[index_of_bucket]);
}

/**
 * 进行 AckListForSingleEpoch 的相等判断
 * @param sfse
 * @param epoch_id
 * @return
 */
int sfse_equal_judgement(struct StatisticsForSingleEpoch *sfse, int epoch_id) {
    if (NULL == sfse) {
        return 1;
    }
    if (sfse->epoch == epoch_id) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * 将一个 AckListForSingleEpoch 添加到 HashBasedAckListForEachEpoch 中
 * @param hbale
 * @param sfse
 * @return
 */
int add_sfse_to_hbale(struct HashBasedAckListForEachEpoch *hbale, struct StatisticsForSingleEpoch *sfse) {
    if (NULL == hbale || NULL == sfse) {
        return NULL_POINTER;
    }
    // 首先找到对应的 bucket
    struct hlist_head *hash_bucket = get_bucket_in_hbale(hbale, sfse->epoch);

    // 如果找不到相应的 bucket
    if (NULL == hash_bucket) {
        return CANNOT_FIND_BUCKET;
    }

    // 检查是否出现了相同的会话表项
    struct StatisticsForSingleEpoch *current_entry = NULL;
    struct hlist_node *next = NULL;
    // 加锁，保护整个 bucket
    spin_lock_bh(&(hbale->lock));
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == sfse_equal_judgement(current_entry, sfse->epoch)) {
            free_sfse(sfse);
            spin_unlock_bh(&(hbale->lock));
            return ALREADY_EXISTS;
        }
    }

    // 这里直接添加到选中的 bucket 之中
    INIT_HLIST_NODE(&sfse->pointer);
    hlist_add_head(&sfse->pointer, hash_bucket);

    // 进行锁的释放
    spin_unlock_bh(&(hbale->lock));
    return ADD_SUCCESS;
}

void increment_sfse_sampling_packets(struct StatisticsForSingleEpoch* sfse){
    if(NULL != sfse){
        spin_lock_bh(&(sfse->lock));
        sfse->number_of_sampling_packets += 1;
        spin_unlock_bh(&(sfse->lock));
    }
}

void increment_sfse_unsampling_packets(struct StatisticsForSingleEpoch* sfse){
    if(NULL != sfse){
        spin_lock_bh(&(sfse->lock));
        sfse->number_of_unsampling_packets += 1;
        spin_unlock_bh(&(sfse->lock));
    }
}

int get_sfse_sampling_packets(struct StatisticsForSingleEpoch* sfse){
    int value = 0;
    if(NULL != sfse){
        spin_lock_bh(&(sfse->lock));
        value = sfse->number_of_sampling_packets;
        spin_unlock_bh(&(sfse->lock));
    }
    return value;
}

int get_sfse_unsampling_packets(struct StatisticsForSingleEpoch* sfse){
    int value = 0;
    if(NULL != sfse){
        spin_lock_bh(&(sfse->lock));
        value = sfse->number_of_unsampling_packets;
        spin_unlock_bh(&(sfse->lock));
    }
    return value;
}


/**
 * 根据 epoch_id 从 HashBasedAckListForEachEpoch 中找到对应的 AckListForSingleEpoch
 * @param hbale
 * @param epoch_id
 * @return
 */
struct StatisticsForSingleEpoch *find_sfse_in_hbale(struct HashBasedAckListForEachEpoch *hbale, int epoch_id) {
    struct hlist_head *hash_bucket = get_bucket_in_hbale(hbale, epoch_id);
    struct StatisticsForSingleEpoch *current_entry = NULL;
    struct hlist_node *next = NULL;
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find sfse because cannot find hash bucket");
        return NULL;
    }
    // 进行加锁
    spin_lock_bh(&(hbale->lock));
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == sfse_equal_judgement(current_entry, epoch_id)) {
            spin_unlock_bh(&(hbale->lock));
            return current_entry;
        }
    }
    // 进行锁的释放
    spin_unlock_bh(&(hbale->lock));
    LOG_WITH_PREFIX("cannot find sfse because cannot find matching epoch in the hash bucket");
    return NULL;
}

void update_sfse_expected_ack_and_timestamp(struct StatisticsForSingleEpoch *sfse,
                                            u64 current_timestamp,
                                            int sampling_router_index) {
    if (NULL == sfse) {
        return;
    }
    // 加锁, 保护整个 AckListForSingleEpoch
    spin_lock_bh(&(sfse->lock));
    // 更新时间戳
    sfse->rtt_estimators[sampling_router_index].last_send_timestamp = current_timestamp;
    // 增加预期收到的 ack 的计数
    sfse->expected_acks[sampling_router_index] += 1;
    // 进行锁的释放
    spin_unlock_bh(&(sfse->lock));
}

void update_sfse_with_new_ack(struct StatisticsForSingleEpoch *sfse, int sampling_router_index, u64 rtt_sample) {
    if (NULL == sfse || sampling_router_index >= sfse->number_of_sample_nodes) {
        return;
    }
    // 加锁，保护整个 AckListForSingleEpoch
    spin_lock_bh(&(sfse->lock));
    // 更新收到的 ACK 的信息
    sfse->received_acks[sampling_router_index] += 1; // 标记这个 ACK 已经收到
    // 更新 RTT 估计器
    update_rtt(&(sfse->rtt_estimators[sampling_router_index]), rtt_sample);
    // 进行锁的释放
    spin_unlock_bh(&(sfse->lock));
}

u64 get_timeout_timestamp(struct StatisticsForSingleEpoch *sfse) {
    if (NULL == sfse) {
        return 0;
    }
    u64 timeout_timestamp = 0;
    int index;

    spin_lock_bh(&(sfse->lock));
    for (index = 0; index < sfse->number_of_sample_nodes; index++) {
        struct RttEstimator *rtt_estimator = &(sfse->rtt_estimators[index]);
        u64 timeout_moment = rtt_estimator->last_send_timestamp + rtt_estimator->rto_us;
        if (timeout_moment > timeout_timestamp) {
            timeout_timestamp = timeout_moment;
        }
    }
    spin_unlock_bh(&(sfse->lock));

    return timeout_timestamp;
}

bool received_enough_acks(struct StatisticsForSingleEpoch *sfse, int min_ack_for_rtt_estimation) {
    bool result = true;
    int index;
    char buffer[1024];
    buffer[0] = '\0';
    spin_lock_bh(&(sfse->lock));
    // 找到第一个不满足的节点
    for (index = 0; index < sfse->number_of_sample_nodes; index++) {
        char string[20];
        if (index != (sfse->number_of_sample_nodes - 1)) {
            snprintf(string, sizeof(string), "%d,%d,",
                     sfse->received_acks[index], sfse->expected_acks[index]);
            strcat(buffer, string);
        } else {
            snprintf(string, sizeof(string), "%d,%d",
                     sfse->received_acks[index], sfse->expected_acks[index]);
            strcat(buffer, string);
        }
        if (sfse->received_acks[index] < min_ack_for_rtt_estimation) {
            result = false;
        }
    }
    spin_unlock_bh(&(sfse->lock));
    return result;
}

void write_response_string_for_fixed_batch(struct StatisticsForSingleEpoch* sfse, char* response_buffer, int current_retrieve_epoch){
    if(NULL == sfse){
        LOG_WITH_PREFIX("write response string failed since sfse is null");
        return;
    }
    spin_lock_bh(&(sfse->lock));
    char epoch_string[40];
    snprintf(epoch_string, sizeof(epoch_string), "%d,%llu,%d,", current_retrieve_epoch,
             sfse->end_sending_timestamp-sfse->start_sending_timestamp, sfse->number_of_sample_nodes);
    strcat(response_buffer, epoch_string);
    int index;
    for (index = 0; index < sfse->number_of_sample_nodes; index++) {
        char current_string[20];
        if (index != (sfse->number_of_sample_nodes - 1)) {
            snprintf(current_string, sizeof(current_string), "%d,%d,",
                     sfse->received_acks[index],
                     sfse->expected_acks[index]);
        } else {
            snprintf(current_string, sizeof(current_string), "%d,%d,",
                     sfse->received_acks[index],
                     sfse->expected_acks[index]);
        }
        strcat(response_buffer, current_string);
    }
    spin_unlock_bh(&(sfse->lock));
}

void write_response_string_for_dynamic_batch(struct StatisticsForSingleEpoch* sfse, char* response_buffer, int current_retrieve_epoch){
    if(NULL == sfse){
        LOG_WITH_PREFIX("write response string failed since sfse is null");
        return;
    }
    spin_lock_bh(&(sfse->lock));
    char epoch_string[50];
    snprintf(epoch_string, sizeof(epoch_string), "%d,%llu,%llu,%d,%d,",
             current_retrieve_epoch,
             sfse->collect_enough_ack_time_stamp - sfse->start_sending_timestamp,
             sfse->reach_timeout_time_stamp - sfse->collect_enough_ack_time_stamp,
             sfse->number_of_sampling_packets,
             sfse->number_of_unsampling_packets);
    strcat(response_buffer, epoch_string);
    int index;
    for (index = 0; index < sfse->number_of_sample_nodes; index++) {
        char current_string[20];
        if (index != (sfse->number_of_sample_nodes - 1)) {
            snprintf(current_string, sizeof(current_string), "%d,%d,",
                     sfse->received_acks[index],
                     sfse->expected_acks[index]);
        } else {
            snprintf(current_string, sizeof(current_string), "%d,%d",
                     sfse->received_acks[index],
                     sfse->expected_acks[index]);
        }
        strcat(response_buffer, current_string);
    }
    //    printk(KERN_EMERG "response buffer: %s\n", response_buffer);
    spin_unlock_bh(&(sfse->lock));
}

//void increment_current_epoch_sent_packets(struct StatisticsForSingleEpoch* sfse){
//    if(NULL != sfse){
//        sfse->number_of_sent_packets += 1;
//    } else {
//        LOG_WITH_PREFIX("sfse is null cannot increment");
//    }
//}