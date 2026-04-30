#ifndef PATH_VALIDATION_MODULE_HASH_BASED_ACK_CACHE_TABLE_H
#define PATH_VALIDATION_MODULE_HASH_BASED_ACK_CACHE_TABLE_H
#include <net/ip.h>

struct HashBasedAckCacheTableForEachEpoch{
    // 总共的桶的数量
    int bucket_count;
    // 真实数组, 存储各个桶, 肯定需要使用指针
    struct hlist_head* bucket_array;
    // 自旋锁
    spinlock_t lock;
};

struct HashBasedAckCacheTableForSingleEpoch {
    // epoch id
    int epoch_id;
    // 桶的数量
    int bucket_count;
    // 存储各个桶
    struct hlist_head* bucket_array;
    // 哈希表节点
    struct hlist_node pointer;
    // 自旋锁
    spinlock_t lock;
};

struct AckCacheEntry {
    int sample_router_index; // 是在当前路径上的第几个节点需要进行采样
    unsigned char* ack_cache; // ack 的预期内容缓存
    u64 current_timestamp; // 当前时间戳
    struct hlist_node pointer;
};

// HashBasedAckCacheTableForSingleEpoch (hbace 的相关操作)
// --------------------------------------------------------
struct HashBasedAckCacheTableForEachEpoch* init_hbace(int bucket_count);

void free_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace);

struct hlist_head* get_bucket_in_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace, int epoch_id);

int add_hbase_to_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace, struct HashBasedAckCacheTableForSingleEpoch* hbase);

struct HashBasedAckCacheTableForSingleEpoch* find_hbase_in_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace, int epoch_id);
// --------------------------------------------------------

// HashBasedAckCacheTableForSingleEpoch (hbase 的相关操作)
// --------------------------------------------------------
struct HashBasedAckCacheTableForSingleEpoch* init_hbase(int bucket_count, int epoch_id);

void free_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase);

void free_hbase_with_pointer(struct HashBasedAckCacheTableForSingleEpoch* hbase);

int hbase_equal_judgement(struct HashBasedAckCacheTableForSingleEpoch* hbase, int epoch_id);

struct hlist_head* get_bucket_in_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase, unsigned char* ack_cache);

struct AckCacheEntry* find_cache_entry_in_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase, unsigned char* ack_cache);

int add_entry_to_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase, struct AckCacheEntry* ack_cache_entry);
// --------------------------------------------------------

// AckCacheEntry 的相关操作
// --------------------------------------------------------
struct AckCacheEntry* create_ack_cache_entry(int router_index, unsigned char* ack_cache, u64 current_timestamp);

/* 释放 AckCacheEntry 及其 ack_cache 指向的缓冲区 */
void free_ack_cache_entry(struct AckCacheEntry* ack_cache_entry);

void free_ack_cache_entry_with_pointer(struct AckCacheEntry* current_ack_entry);

int ack_cache_entry_equal_judegment(struct AckCacheEntry* ack_cache_entry, unsigned char* ack_cache);
// --------------------------------------------------------

#endif

