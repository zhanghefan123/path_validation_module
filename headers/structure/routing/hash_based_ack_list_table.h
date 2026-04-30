//
// Created by zhf on 2026/3/30.
//

#ifndef PATH_VALIDATION_MODULE_HASH_BASED_ACK_LIST_TABLE_H
#define PATH_VALIDATION_MODULE_HASH_BASED_ACK_LIST_TABLE_H

#include "structure/rtt_estimator/rtt_estimator.h"

struct HashBasedAckListForEachEpoch {
    // 总共的桶的数量
    int bucket_count;
    // 真实数组，存储各个桶, 肯定需要使用指针
    struct hlist_head *bucket_array;
    // 自旋锁
    spinlock_t lock;
};

struct StatisticsForSingleEpoch {
    // 当前对应的 epoch 是什么
    int epoch;
    // 一个批次最后一个包发送出去的时间
    u64 timeout_timestamp;
    // 总的表项的数量
    int number_of_sample_nodes;
    // 预期的 ack 计数
    int *expected_acks;
    // 收到的 ack 计数
    int *received_acks;
    // 当前 epoch 预计要发送的包的数量
    int batch_size;
    // 当前 epoch 发送的包的数量
    int number_of_sampling_packets;
    // 当前 epoch 未采样的数据包的量
    int number_of_unsampling_packets;
    // 记录这个 epoch 开始发送的时间
    u64 start_sending_timestamp;
    // 记录这个 epoch 结束发送的时间
    u64 end_sending_timestamp;
    // 记录直到超时的时间开销
    u64 reach_timeout_time_stamp;
    // 记录直到收集齐所有的包的时间开销
    u64 collect_enough_ack_time_stamp;
    // 是否已经收齐了 ack 了
    bool already_collected_acks;
    // 所有的 rtt 超时计时器
    struct RttEstimator *rtt_estimators;
    // 哈希表节点
    struct hlist_node pointer;
    // 自旋锁
    spinlock_t lock;
};

// HashBasedAckListForEachEpoch hbale 的相关操作
// -----------------------------------------------------------------
struct HashBasedAckListForEachEpoch *init_hbale(int bucket_count);

void free_hbale(struct HashBasedAckListForEachEpoch *hbale);

struct hlist_head *get_bucket_in_hbale(struct HashBasedAckListForEachEpoch *hbale, int epoch_id);

struct StatisticsForSingleEpoch *find_sfse_in_hbale(struct HashBasedAckListForEachEpoch *hbale, int epoch_id);

int add_sfse_to_hbale(struct HashBasedAckListForEachEpoch *hbale, struct StatisticsForSingleEpoch *sfse);

void increment_sfse_sampling_packets(struct StatisticsForSingleEpoch* sfse);

void increment_sfse_unsampling_packets(struct StatisticsForSingleEpoch* sfse);

int get_sfse_sampling_packets(struct StatisticsForSingleEpoch* sfse);

int get_sfse_unsampling_packets(struct StatisticsForSingleEpoch* sfse);
// -----------------------------------------------------------------


// StatisticsForSingleEpoch sfse 的相关操作
// -----------------------------------------------------------------

//struct StatisticsForSingleEpoch* init_sfse_for_dynamic_batch(int number_of_sample_nodes, int epoch_id);

struct StatisticsForSingleEpoch *init_sfse(int number_of_sample_nodes, int epoch_id, int batch_size);

void free_sfse(struct StatisticsForSingleEpoch *sfse);

void free_sfse_with_pointer(struct StatisticsForSingleEpoch *sfse);

int sfse_equal_judgement(struct StatisticsForSingleEpoch *sfse, int epoch_id);

void update_sfse_expected_ack_and_timestamp(struct StatisticsForSingleEpoch *sfse,
                                            u64 current_timestamp,
                                            int sampling_router_index);

void update_sfse_with_new_ack(struct StatisticsForSingleEpoch *sfse, int sampling_router_index, u64 rtt_sample);

u64 get_timeout_timestamp(struct StatisticsForSingleEpoch *sfse);

bool received_enough_acks(struct StatisticsForSingleEpoch *sfse, int min_ack_for_rtt_estimation);

void write_response_string_for_fixed_batch(struct StatisticsForSingleEpoch* sfse, char* response_buffer, int current_retrieve_epoch);

void write_response_string_for_dynamic_batch(struct StatisticsForSingleEpoch* sfse, char* response_buffer, int current_retrieve_epoch);

//void increment_current_epoch_sent_packets(struct StatisticsForSingleEpoch* sfse);
// -----------------------------------------------------------------

#endif //PATH_VALIDATION_MODULE_HASH_BASED_ACK_LIST_TABLE_H
