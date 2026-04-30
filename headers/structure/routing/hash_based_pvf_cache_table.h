//
// Created by zhf on 2025/12/14.
//

#ifndef PATH_VALIDATION_MODULE_HASH_BASED_PVF_CACHE_TABLE_H
#define PATH_VALIDATION_MODULE_HASH_BASED_PVF_CACHE_TABLE_H
#include "structure/header/opt_header.h"

#define MAX_PATH_STR_LENGTH 2048

struct HashBasedPvfCacheTable {
    // 总共的桶的数量
    int bucket_count;
    // 真实链表
    struct hlist_head* bucket_array;
};

struct CacheEntry{
    int length_of_path;
    int* node_ids;
    unsigned char* pvf_pointer;  // pvf 缓存
    struct hlist_node pointer;
};

struct CacheEntry* create_cache_entry(int* node_ids, int path_length, unsigned char* pvf_pointer);

void free_cache_entry(struct CacheEntry* cache_entry);

int cache_entry_equal_judgement(struct CacheEntry* cache_entry, int* node_ids, int path_length);

struct HashBasedPvfCacheTable* init_hbpct(int bucket_count);

void free_hbpct(struct HashBasedPvfCacheTable* hbpct);

u64 calculate_hash_based_on_node_ids(int* node_ids, int path_length);

struct hlist_head* get_bucket_in_hbpct(struct HashBasedPvfCacheTable* hbpct, int* node_ids, int path_length);

struct CacheEntry* find_cache_entry_in_hbpct(struct HashBasedPvfCacheTable* hbpct, int* node_ids, int path_length);

int add_entry_to_hbpct(struct HashBasedPvfCacheTable* hbpct, struct CacheEntry* cache_entry);

#endif //PATH_VALIDATION_MODULE_HASH_BASED_PVF_CACHE_TABLE_H
