#include "tools/tools.h"
#include "structure/header/sec_path_mab_header.h"
#include "structure/routing/table_common.h"
#include "structure/header/sec_path_mab_ack_header.h"
#include "structure/routing/hash_based_ack_cache_table.h"

/**
 * @file hash_based_ack_cache_table.c
 * @brief 基于哈希的 ACK 缓存表实现
 *
 * 该模块实现了一个双层哈希表结构用于缓存 ACK 信息：
 * - 大 map (HashBasedAckCacheTableForEachEpoch): 按 epoch 索引
 * - 小 map (HashBasedAckCacheTableForSingleEpoch): 每个 epoch 内的 ACK 缓存
 *
 * 作者: 安全路径验证模块团队
 * 日期: 2026
 */

/**
 * 初始化大 map
 *
 * 分配并初始化一个按 epoch 索引的哈希表结构。
 * 该结构包含一个哈希桶数组，每个桶用于存放对应 epoch 的小 map。
 *
 * @param bucket_count 哈希桶的数量，将用于对 epoch_id 取模
 * @return 成功返回指向初始化后的 HashBasedAckCacheTableForEachEpoch 结构指针
 *         失败返回 NULL
 *
 * 注意：调用者负责在不再需要时调用 free_hbace() 释放内存
 */
struct HashBasedAckCacheTableForEachEpoch* init_hbace(int bucket_count){
    struct HashBasedAckCacheTableForEachEpoch* hbace = (struct HashBasedAckCacheTableForEachEpoch*)(kmalloc(sizeof(struct HashBasedAckCacheTableForEachEpoch), GFP_KERNEL));

    // 准备初始化一个哈希表
    hbace->bucket_count = bucket_count;
    struct hlist_head* head_pointer_list = NULL;
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
    hbace->bucket_count = bucket_count;
    hbace->bucket_array = head_pointer_list;

    // 初始化自旋锁
    spin_lock_init(&hbace->lock);

    return hbace;
}

/**
 * 释放大 map
 *
 * 遍历大 map 中的所有哈希桶，释放每个桶中的小 map 结构，
 * 最后释放桶数组和大 map 本身。
 *
 * @param hbace 指向 HashBasedAckCacheTableForEachEpoch 结构体的指针
 *
 * 注意：每个桶中的小 map 会通过 free_hbase_with_pointer() 释放，
 *       该函数会同时从哈希表中移除并释放小 map 结构
 */
void free_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace){
    // 基础判断
    if(NULL == hbace){
        LOG_WITH_PREFIX("cannot free hbace since hbace is NULL");
        return;
    }
    int index;
    // 释放 bucket_array
    struct hlist_head* hash_bucket = NULL;
    struct HashBasedAckCacheTableForSingleEpoch* current_entry  = NULL;
    struct hlist_node* next;
    for (index = 0; index < hbace->bucket_count; index++) {
        hash_bucket = &(hbace->bucket_array[index]);
        // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
        if (NULL == hash_bucket) {
            LOG_WITH_PREFIX("hash bucket is null");
            return;
        }
        spin_lock_bh(&(hbace->lock));
        hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
            if (NULL != current_entry) {
                free_hbase_with_pointer(current_entry);
            }
        }
        spin_unlock_bh(&(hbace->lock));
    }
    // 释放 hbace
    kfree(hbace->bucket_array);
    kfree(hbace);
}

/**
 * 初始化小 map
 *
 * 分配并初始化一个针对单个 epoch 的哈希表结构。
 * 该结构包含一个哈希桶数组，用于存储 ACK 缓存条目。
 *
 * @param bucket_count 哈希桶的数量，将用于对 ack_cache 取模
 * @param epoch_id    该小 map 对应的 epoch 标识符
 * @return 成功返回指向初始化后的 HashBasedAckCacheTableForSingleEpoch 结构指针
 *         失败返回 NULL
 *
 * 注意：调用者负责在不再需要时调用 free_hbase() 释放内存
 */
struct HashBasedAckCacheTableForSingleEpoch* init_hbase(int bucket_count, int epoch_id){
    struct HashBasedAckCacheTableForSingleEpoch* hbase = (struct HashBasedAckCacheTableForSingleEpoch*)(kmalloc(sizeof(struct HashBasedAckCacheTableForSingleEpoch), GFP_KERNEL));
    // 设置 epoch id
    hbase->epoch_id = epoch_id;
    // 准备初始化一个哈希表
    hbase->bucket_count = bucket_count;
    struct hlist_head* head_pointer_list = NULL;
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
    hbase->bucket_count = bucket_count;
    hbase->bucket_array = head_pointer_list;
    // 初始化自旋锁
    spin_lock_init(&(hbase->lock));

    return hbase;
}

/**
 * 释放小 map
 *
 * 遍历小 map 中的所有哈希桶，释放每个桶中的 ACK 缓存条目，
 * 最后释放桶数组和小 map 本身。
 *
 * @param hbase 指向 HashBasedAckCacheTableForSingleEpoch 结构体的指针
 *
 * 注意：每个桶中的 ACK 缓存条目会通过 free_ack_cache_entry_with_pointer() 释放
 */
void free_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase){
    if(NULL == hbase){
        LOG_WITH_PREFIX("hbase is NULL");
        return;
    }
    int index;
    // 释放 bucket_array
    struct hlist_head* hash_bucket = NULL;
    struct AckCacheEntry* current_ack_entry  = NULL;
    struct hlist_node* next;
    // printk(KERN_EMERG "hash bucket count: %d \n", hbpct->bucket_count);
    for (index = 0; index < hbase->bucket_count; index++) {
        hash_bucket = &(hbase->bucket_array[index]);
        // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
        if (NULL == hash_bucket) {
            LOG_WITH_PREFIX("hash bucket is null, cannot be free");
            continue;
        }
        // 进行加锁
        spin_lock_bh(&(hbase->lock));
        hlist_for_each_entry_safe(current_ack_entry, next, hash_bucket, pointer) {
            if (NULL != current_ack_entry) {
                free_ack_cache_entry_with_pointer(current_ack_entry);
            }
        }
        // 进行释放锁
        spin_unlock_bh(&(hbase->lock));
    }
    // 释放 bucket
    kfree(hbase->bucket_array);
    // 释放 hbase
    kfree(hbase);
}

/**
 * 释放小 map（从哈希表中移除后）
 *
 * 先将小 map 从其所属的哈希表中移除，然后调用 free_hbase() 释放内存。
 *
 * @param hbase 指向 HashBasedAckCacheTableForSingleEpoch 结构体的指针
 *
 * 注意：此函数用于需要从哈希表中显式移除小 map 的场景
 * (已经被 hbace->lock 保护了)
 */
void free_hbase_with_pointer(struct HashBasedAckCacheTableForSingleEpoch* hbase){
    if(NULL != hbase){
        hlist_del(&hbase->pointer);
        free_hbase(hbase);
    } else {
        printk(KERN_EMERG "hbase is NULL");
    }
}

/**
 * 释放 ACK 缓存条目（从哈希表中移除后）
 *
 * 先将 ACK 缓存条目从其所属的哈希表中移除，然后调用
 * free_ack_cache_entry() 释放内存。
 *
 * @param current_ack_entry 指向 AckCacheEntry 结构体的指针
 *
 * 注意：此函数用于需要从哈希表中显式移除 ACK 缓存条目的场景
 *
 * (已经被 hbase->lock 保护了，所以不需要在函数内部进行加锁)
 */
void free_ack_cache_entry_with_pointer(struct AckCacheEntry* current_ack_entry){
    if(NULL != current_ack_entry){
        hlist_del(&current_ack_entry->pointer);
        free_ack_cache_entry(current_ack_entry);
    } else {
        printk(KERN_EMERG "ack cache entry is NULL");
    }
}

/**
 * 比较小 map 的 epoch_id
 *
 * 检查给定的 HashBasedAckCacheTableForSingleEpoch 结构体的 epoch_id
 * 是否与指定的 epoch_id 相等。
 *
 * @param hbase   指向 HashBasedAckCacheTableForSingleEpoch 结构体的指针
 * @param epoch_id 要比较的 epoch 标识符
 * @return 成功返回 0，表示 epoch_id 相等
 *         失败返回 -1，表示 epoch_id 不相等或 hbase 为 NULL
 *
 * 注意：该函数用于在大 map 中查找匹配特定 epoch 的小 map
 */
int hbase_equal_judgement(struct HashBasedAckCacheTableForSingleEpoch* hbase, int epoch_id){
    if(NULL == hbase){
        LOG_WITH_PREFIX("hbase is null");
        return -1;
    }
    if(epoch_id == hbase->epoch_id){
        return 0;
    } else {
        return -1;
    }
}

/**
 * 在大 map 中定位哈希桶
 *
 * 根据 epoch_id 计算哈希值，然后在大 map 的桶数组中
 * 找到对应的哈希桶位置。
 *
 * @param hbace    指向大 map (HashBasedAckCacheTableForEachEpoch) 的指针
 * @param epoch_id 用于计算哈希的 epoch 标识符
 * @return 指向对应 epoch_id 的哈希桶的指针
 *
 * 计算方式：epoch_id % bucket_count
 */
struct hlist_head* get_bucket_in_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace, int epoch_id){
    // 获取 hash truncate
    u64 hash_truncate = epoch_id % hbace->bucket_count;
    // 找到对应的桶的索引
    u64 index_of_bucket = hash_truncate % hbace->bucket_count;
    // 进行桶的返回
    return &(hbace->bucket_array[index_of_bucket]);
}

/**
 * 将小 map 添加到大 map
 *
 * 将指定的小 map 结构添加到对应 epoch_id 的哈希桶中。
 * 添加前会检查是否已存在相同 epoch 的小 map，若存在则释放新添加的小 map。
 *
 * @param hbace 指向大 map (HashBasedAckCacheTableForEachEpoch) 的指针
 * @param hbase 指向要添加的小 map (HashBasedAckCacheTableForSingleEpoch) 的指针
 * @return 成功返回 ADD_SUCCESS
 *         若 hbace 或 hbase 为空返回 NULL_POINTER
 *         若找不到桶返回 CANNOT_FIND_BUCKET
 *         若已存在相同 epoch 返回 ALREADY_EXISTS
 *
 * 注意：添加失败时，如果是因为已存在或无法找到桶，函数会负责释放 hbase
 * (已经被 hbace->lock 保护了)
 */
int add_hbase_to_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace, struct HashBasedAckCacheTableForSingleEpoch* hbase){
    if(NULL == hbace || NULL == hbase){
        LOG_WITH_PREFIX("hbace or hbase is null");
        return -1;
    }

    // 首先进行相应的 bucket 的查找
    struct hlist_head* hash_bucket = get_bucket_in_hbace(hbace, hbase->epoch_id);

    // 如果找不到相应的 bucket
    if(NULL == hash_bucket){
        LOG_WITH_PREFIX("cannot find bucket in hbace");
        return CANNOT_FIND_BUCKET;
    }

    // 检查是否出现了相同的会话表项
    struct HashBasedAckCacheTableForSingleEpoch* current_entry = NULL;
    struct hlist_node* next = NULL;

    // 进行加锁
    spin_lock_bh(&(hbace->lock));
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer){
        if(0 == hbase_equal_judgement(current_entry, hbase->epoch_id)){
            LOG_WITH_PREFIX("the same epoch already exists in the hash table");
            free_hbase(hbase);
            spin_unlock_bh(&(hbace->lock));
            return ALREADY_EXISTS;
        }
    }

    // 如果存在的话, 这里直接添加到选中的bucket 之中
    INIT_HLIST_NODE(&hbase->pointer);
    hlist_add_head(&hbase->pointer, hash_bucket);

    // 进行锁的释放
    spin_unlock_bh(&(hbace->lock));

    return ADD_SUCCESS;
}

/**
 * 在大 map 中查找小 map
 *
 * 根据 epoch_id 在大 map 中搜索对应的小 map 结构。
 *
 * @param hbace    指向大 map (HashBasedAckCacheTableForEachEpoch) 的指针
 * @param epoch_id 要查找的 epoch 标识符
 * @return 成功找到返回指向对应小 map 的指针
 *         未找到或失败返回 NULL
 *
 * 注意：使用 get_bucket_in_hbace() 计算哈希桶位置，然后遍历桶中的链表
 */
struct HashBasedAckCacheTableForSingleEpoch* find_hbase_in_hbace(struct HashBasedAckCacheTableForEachEpoch* hbace, int epoch_id){
    struct hlist_head* hash_bucket = get_bucket_in_hbace(hbace, epoch_id);
    struct HashBasedAckCacheTableForSingleEpoch* current_entry = NULL;
    struct hlist_node* next = NULL;
    if(NULL == hash_bucket){
        LOG_WITH_PREFIX("cannot find hbase because cannot find hash bucket");
        return NULL;
    }
    // 进行加锁
    spin_lock_bh(&(hbace->lock));
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer){
        if(0 == hbase_equal_judgement(current_entry, epoch_id)){
            // 进行释放锁
            spin_unlock_bh(&(hbace->lock));
            return current_entry;
        }
    }
    // 进行加锁
    spin_unlock_bh(&(hbace->lock));
    return NULL;
}


/**
 * 在小 map 中定位哈希桶
 *
 * 根据 ack_cache 内容计算哈希值，然后在指定的小 map 的桶数组中
 * 找到对应的哈希桶位置。
 *
 * @param hbase    指向小 map (HashBasedAckCacheTableForSingleEpoch) 的指针
 * @param ack_cache 指向 ACK 缓存数据的指针，用于计算哈希
 * @return 指向对应哈希桶的指针
 *
 * 计算方式：将 ack_cache 的前 8 字节解释为 u64，然后对 bucket_count 取模
 *
 * (无需加锁，因为该函数只是计算哈希桶位置，并不涉及对数据结构的修改或访问)
 */
struct hlist_head* get_bucket_in_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbact, unsigned char* ack_cache){
    // 获取 hash truncate
    u64 hash_truncate = *((u64*)(ack_cache));
    // 找到对应的桶的索引
    u64 index_of_bucket;
    index_of_bucket = hash_truncate % hbact->bucket_count;
    // 返回对应的桶
    return &hbact->bucket_array[index_of_bucket];
}

/**
 * 在小 map 中查找 ACK 缓存条目
 *
 * 根据 ack_cache 内容在小 map 中搜索对应的 ACK 缓存条目。
 *
 * @param hbase    指向小 map (HashBasedAckCacheTableForSingleEpoch) 的指针
 * @param ack_cache 指向 ACK 缓存数据的指针
 * @return 成功找到返回指向对应 AckCacheEntry 的指针
 *         未找到或失败返回 NULL
 *
 * 注意：使用 ack_cache_entry_equal_judegment() 进行条目比较
 * (已经被 hbase->lock 保护了)
 */
struct AckCacheEntry* find_cache_entry_in_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase, unsigned char* ack_cache){
    struct hlist_head *hash_bucket = NULL;
    struct AckCacheEntry *current_ack_entry = NULL;
    struct hlist_node *next;
    hash_bucket = get_bucket_in_hbase(hbase, ack_cache);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    // 进行加锁
    spin_lock_bh(&(hbase->lock));
    hlist_for_each_entry_safe(current_ack_entry, next, hash_bucket, pointer) {
        if (0 == ack_cache_entry_equal_judegment(current_ack_entry, ack_cache)) {
            // 进行释放锁
            spin_unlock_bh(&(hbase->lock));
            return current_ack_entry;
        }
    }
    // 进行释放锁
    spin_unlock_bh(&(hbase->lock));
    return NULL;
}

/**
 * 将 ACK 缓存条目添加到小 map
 *
 * 将指定的 ACK 缓存条目添加到对应 ack_cache 的哈希桶中。
 * 添加前会检查是否已存在相同的条目，若存在则释放新条目。
 *
 * @param hbact           指向小 map (HashBasedAckCacheTableForSingleEpoch) 的指针
 * @param ack_cache_entry 指向要添加的 ACK 缓存条目的指针
 * @return 成功返回 ADD_SUCCESS
 *         若 hbact 或 ack_cache_entry 为空返回 NULL_POINTER
 *         若找不到桶返回 CANNOT_FIND_BUCKET
 *         若已存在相同条目返回 ALREADY_EXISTS
 *
 * 注意：添加失败时，如果是因为已存在或无法找到桶，函数会负责释放 ack_cache_entry
 * (已经被 hbase->lock 保护了)
 */
int add_entry_to_hbase(struct HashBasedAckCacheTableForSingleEpoch* hbase, struct AckCacheEntry* ack_cache_entry){
    if(NULL == hbase || NULL == ack_cache_entry){
        return NULL_POINTER;
    }

    struct hlist_head *hash_bucket = NULL;
    struct AckCacheEntry *current_entry = NULL;
    struct hlist_node *next = NULL;
    // 首先找到对应的应该存放的 bucket
    hash_bucket = get_bucket_in_hbase(hbase, ack_cache_entry->ack_cache);
    if (NULL == hash_bucket) {
        free_ack_cache_entry(ack_cache_entry);
        LOG_WITH_PREFIX("cannot find bucket");
        return CANNOT_FIND_BUCKET;
    }
    // 进行加锁
    spin_lock_bh(&(hbase->lock));
    // 检查是否出现了相同的会话表项
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == ack_cache_entry_equal_judegment(current_entry, ack_cache_entry->ack_cache)) {
            free_ack_cache_entry(ack_cache_entry);
            spin_unlock_bh(&(hbase->lock));
            LOG_WITH_PREFIX("already exists");
            return ALREADY_EXISTS;
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&ack_cache_entry->pointer);
    hlist_add_head(&ack_cache_entry->pointer, hash_bucket);

    // 进行锁的释放
    spin_unlock_bh(&(hbase->lock));

    return ADD_SUCCESS;
}

/**
 * 创建 ACK 缓存条目
 *
 * 分配并初始化一个新的 ACK 缓存条目结构。
 *
 * @param sample_router_index 样本路由器索引
 * @param ack_cache          指向 ACK 缓存数据的指针
 * @return 成功返回指向初始化后的 AckCacheEntry 结构指针
 *         失败返回 NULL
 *
 * 注意：调用者负责在不再需要时调用 free_ack_cache_entry() 释放内存
 *
 * (不需要在函数内部进行加锁，因为创建条目时还未添加到哈希表中，不存在并发访问问题)
 */
struct AckCacheEntry* create_ack_cache_entry(int sample_router_index, unsigned char* ack_cache, u64 current_timestamp){
    struct AckCacheEntry* ack_cache_entry = (struct AckCacheEntry*)(kmalloc(sizeof(struct AckCacheEntry), GFP_KERNEL));
    ack_cache_entry->sample_router_index = sample_router_index;
    ack_cache_entry->ack_cache = (unsigned char*)(kmalloc(sizeof(unsigned char) * ACK_AUTHENTICATION_LENGTH, GFP_KERNEL));
    memcpy(ack_cache_entry->ack_cache, ack_cache, ACK_AUTHENTICATION_LENGTH);
    ack_cache_entry->current_timestamp = current_timestamp;
    return ack_cache_entry;
}

/**
 * 释放 ACK 缓存条目
 *
 * 释放 ACK 缓存条目占用的内存，包括其内部的 ack_cache 数据。
 *
 * @param ack_cache_entry 指向要释放的 AckCacheEntry 结构体的指针
 *
 * 注意：会依次释放内部的 ack_cache 缓冲区和条目结构本身
 * (已经被 hbase->lock 保护了，所以不需要在函数内部进行加锁)
 */
void free_ack_cache_entry(struct AckCacheEntry* ack_cache_entry){
    if(NULL != ack_cache_entry){
        if(NULL != ack_cache_entry->ack_cache){
            kfree(ack_cache_entry->ack_cache);
        } else {
            printk(KERN_EMERG "ack_cache_entry->ack_cache is NULL");
        }
    } else {
        printk(KERN_EMERG "ack cache entry is NULL");
    }
}

/**
 * 比较 ACK 缓存条目
 *
 * 检查给定的 AckCacheEntry 的 ack_cache 数据是否与指定的 ack_cache 相同。
 * 比较长度为 ACK_VALIDATION_PART_SIZE 字节。
 *
 * @param ack_cache_entry 指向 AckCacheEntry 结构体的指针
 * @param ack_cache       指向要比较的 ACK 缓存数据的指针
 * @return 相等返回 0
 *         不相等返回 1
 *         若 ack_cache_entry 为 NULL 行为未定义
 *
 * 注意：该函数用于在小 map 的哈希桶中查找匹配的条目
 * (已经被 hbase->lock 保护了，所以不需要在函数内部进行加锁)
 */
int ack_cache_entry_equal_judegment(struct AckCacheEntry* ack_cache_entry, unsigned char* ack_cache){
    // compare ack cache
    bool equal = memory_compare(ack_cache_entry->ack_cache, ack_cache, ACK_VALIDATION_PART_SIZE);
    if(equal) {
        return 0;
    } else {
        return 1;
    }
}

