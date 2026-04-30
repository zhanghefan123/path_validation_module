#include <linux/list.h>
#include "tools/tools.h"
#include "structure/routing/hash_based_pvf_cache_table.h"
#include "structure/routing/table_common.h"

struct CacheEntry* create_cache_entry(int* node_ids, int path_length, unsigned char* pvf_pointer){
    //    -----------------------------------------------------------------------------------------------------
    struct CacheEntry* cache_entry = (struct CacheEntry*)(kmalloc(sizeof(struct CacheEntry), GFP_KERNEL));
    cache_entry->length_of_path = path_length;
    cache_entry->node_ids = (int*)(kmalloc(sizeof(int) * path_length, GFP_KERNEL));
    memcpy(cache_entry->node_ids, node_ids, sizeof(int) * path_length);
    cache_entry->pvf_pointer = pvf_pointer;
    return cache_entry;
    //    -----------------------------------------------------------------------------------------------------
//    struct CacheEntry* cache_entry = (struct CacheEntry*)(kmalloc(sizeof(struct CacheEntry), GFP_KERNEL));
//    cache_entry->length_of_path_str = strlen(path_str_pointer) + 1;
//    cache_entry->path_str = (char*)(kmalloc(sizeof(char) * (strlen(path_str_pointer)+1), GFP_KERNEL));
}

void free_cache_entry(struct CacheEntry* cache_entry){
    if(NULL != cache_entry){
        if(NULL != cache_entry->node_ids){
            kfree(cache_entry->node_ids);
        }
        kfree(cache_entry);
    }
}


int cache_entry_equal_judgement(struct CacheEntry* cache_entry, int* node_ids, int path_length){
    if (NULL == cache_entry){
        return 1;
    }
    if ((path_length == (cache_entry->length_of_path)) && (memory_compare_ints(node_ids, cache_entry->node_ids, path_length))){
        return 0;
    } else {
        return 1;
    }
}

struct HashBasedPvfCacheTable* init_hbpct(int bucket_count){
    struct HashBasedPvfCacheTable* hbpct = (struct HashBasedPvfCacheTable*)(kmalloc(sizeof(struct HashBasedPvfCacheTable), GFP_KERNEL));

    // 准备初始化一个哈希表
    // ----------------------------------------------------------------------------------------------------------------------------------------------------
    hbpct->bucket_count = bucket_count;
    struct hlist_head* head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * bucket_count, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
    }
    // 初始化表头
    int index;
    for (index = 0; index < bucket_count; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    hbpct->bucket_count = bucket_count;
    hbpct->bucket_array = head_pointer_list;
    // ----------------------------------------------------------------------------------------------------------------------------------------------------

    return hbpct;
}

void free_hbpct(struct HashBasedPvfCacheTable* hbpct){
    if(NULL != hbpct) {
        // 释放 bucket_array
        // ----------------------------------------------------------------------------
        if (NULL != hbpct->bucket_array) {
            int index;
            struct hlist_head *hash_bucket = NULL;
            struct CacheEntry *current_entry = NULL;
            struct hlist_node *next;
            for (index = 0; index < hbpct->bucket_count; index++) {
                hash_bucket = &(hbpct->bucket_array[index]);
                // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
                if (NULL == hash_bucket) {
                    LOG_WITH_PREFIX("hash bucket is null");
                    return;
                }
                hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
                    if (NULL != current_entry) {
                        hlist_del(&current_entry->pointer);
                        free_cache_entry(current_entry);
                    }
                }
            }
            kfree(hbpct->bucket_array);
        }
        // ----------------------------------------------------------------------------
        kfree(hbpct);
    }
}

u64 calculate_hash_based_on_node_ids(int* node_ids, int path_length){
    u32 hash_value = jhash(node_ids, sizeof(int) * path_length, 1234);
    return hash_value;
}

struct hlist_head* get_bucket_in_hbpct(struct HashBasedPvfCacheTable* hbpct, int* node_ids, int path_length){
    // 获取 hash truncate
    u64 hash_truncate = calculate_hash_based_on_node_ids(node_ids, path_length);
    // 找到对应的桶的索引
    u64 index_of_bucket;
    index_of_bucket = hash_truncate % hbpct->bucket_count;
    // 返回对应的桶
    return &hbpct->bucket_array[index_of_bucket];
}

struct CacheEntry* find_cache_entry_in_hbpct(struct HashBasedPvfCacheTable* hbpct, int* node_ids, int path_length){
    struct hlist_head *hash_bucket = NULL;
    struct CacheEntry *current_entry = NULL;
    struct hlist_node *next;
    // printk(KERN_EMERG "path_str_length:%d\n", strlen(path_str));
    hash_bucket = get_bucket_in_hbpct(hbpct, node_ids, path_length);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == cache_entry_equal_judgement(current_entry, node_ids, path_length)) {
            return current_entry;
        }
    }
    return NULL;
}

int add_entry_to_hbpct(struct HashBasedPvfCacheTable* hbpct, struct CacheEntry* cache_entry){
    struct hlist_head *hash_bucket = NULL;
    struct CacheEntry *current_entry = NULL;
    struct hlist_node *next = NULL;
    // 首先找到对应的应该存放的 bucket
    hash_bucket = get_bucket_in_hbpct(hbpct, cache_entry->node_ids, cache_entry->length_of_path);
    if (NULL == hash_bucket) {
        // 找不到 hash_bucket
        LOG_WITH_PREFIX("cannot find hash bucket");
        free_cache_entry(cache_entry);
        return CANNOT_FIND_BUCKET;
    }
    // 检查是否出现了相同的会话表项
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == cache_entry_equal_judgement(current_entry, cache_entry->node_ids, cache_entry->length_of_path)) {
            LOG_WITH_PREFIX("already exists cache entry");
            free_cache_entry(cache_entry);
            return ALREADY_EXISTS;
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&cache_entry->pointer);
    hlist_add_head(&cache_entry->pointer, hash_bucket);
    return ADD_SUCCESS;
}
