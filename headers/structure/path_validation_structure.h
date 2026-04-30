//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H

#include "structure/crypto/bloom_filter.h"
#include "structure/interface/interface_table.h"
#include "structure/routing/array_based_routing_table.h"
#include "structure/routing/hash_based_ack_list_table.h"
#include "structure/routing/hash_based_routing_table.h"
#include "structure/session/session_table.h"
#include "structure/session/epic_session_table.h"
#include "structure/header/selir_header.h"
#include "structure/routing/array_based_multipath_table.h"
#include "structure/routing/hash_based_pvf_cache_table.h"
#include "structure/header/sec_path_mab_common.h"
#include "structure/routing/hash_based_ack_cache_table.h"
#include "structure/routing/linked_list_based_malicious_params_table.h"
#include "structure/malicious/malicious_params.h"

struct pv_struct {
    struct shash_desc *hash_api;
    struct shash_desc *hmac_api;
    struct BloomFilter *bloom_filter;
    struct HashBasedPvfCacheTable* hbpct;
};

DECLARE_PER_CPU(struct pv_struct, validation_api); // 这里只是声明

struct PathValidationStructure {
    // 当前节点的 id
    int node_id;
    // 路由表的类型
    int routing_table_type;
    // 路由器的类型
    int router_type;
    // 基于数组的路由表
    struct ArrayBasedRoutingTable *abrt;


    // 基于链表的预期接口表 (需要将其弄成一个链表)
    struct HashBasedAckListForEachEpoch* hbale;
    // 基于链表的预期 ack 表
    struct HashBasedAckCacheTableForEachEpoch* hbace;
    // 预计要执行的变更
    struct LinkedListBasedMaliciousParamsTable* llbmpt;

    // 基于哈希的路由表
    struct HashBasedRoutingTable *hbrt;
    // 基于哈希的缓存表
//    struct HashBasedPvfCacheTable *hbpct;
    // 基于数组的接口表
    struct ArrayBasedInterfaceTable *abit;
    // 存储 segment list
    struct ArrayBasedMultipathTable *abpt;
    // 基于哈希的会话表
    struct HashBasedSessionTable *hbst;
    // 基于哈希的 EPIC 会话表
    struct HashBasedEpicSessionTable *hbest;
    // 布隆过滤器
    struct BloomFilter *bloom_filter;
    // selir 信息
    struct SELiRInfo *selir_info;
    // 哈希结构体
    struct shash_desc *hash_api;
    // hmac结构体
    struct shash_desc *hmac_api;
    // LiR 单次插入的链路标识的个数
    int lir_single_time_encoding_count;
    // sec path mab settings
    struct SecPathMabSettings* sec_path_mab_settings;
};

struct PathValidationStructure *init_pvs(void);

void free_pvs(struct PathValidationStructure *pvs);

struct pv_struct create_pv_struct(bool required_hash, bool required_hmac, bool required_bloom_filter,
                                  struct BloomFilter *template_bloom_filter);

void free_pv_struct(struct pv_struct *pv_struct);

void initialize_routing_table(struct PathValidationStructure *pvs,
                              int routing_table_type,
                              int number_of_routes_or_buckets);

void initialize_forwarding_table(struct PathValidationStructure *pvs, int number_of_interfaces);

void initialize_multipath_table(struct PathValidationStructure *pvs, int multipath_routing_type, int number_of_buckets,
                                int number_of_destinations, int number_of_relationships, int number_of_paths);

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
