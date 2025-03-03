//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H

#include "structure/crypto/bloom_filter.h"
#include "structure/interface/interface_table.h"
#include "structure/routing/array_based_routing_table.h"
#include "structure/routing/hash_based_routing_table.h"
#include "structure/session/session_table.h"
#include "structure/header/selir_header.h"

struct PathValidationStructure {
    // 当前节点的 id
    int node_id;
    // 路由表的类型
    int routing_table_type;
    // 基于数组的路由表
    struct ArrayBasedRoutingTable *abrt;
    // 基于哈希的路由表
    struct HashBasedRoutingTable *hbrt;
    // 基于数组的接口表
    struct ArrayBasedInterfaceTable *abit;
    // 基于哈希的会话表
    struct HashBasedSessionTable* hbst;
    // 布隆过滤器
    struct BloomFilter *bloom_filter;
    // selir 信息
    struct SELiRInfo* selir_info;
    // 哈希结构体
    struct shash_desc* hash_api;
    // hmac结构体
    struct shash_desc* hmac_api;
};

struct PathValidationStructure *init_pvs(void);

void free_pvs(struct PathValidationStructure *pvs);

void initialize_routing_and_forwarding_table(struct PathValidationStructure *pvs,
                                             int routing_table_type,
                                             int number_of_routes_or_buckets,
                                             int number_of_interfaces);

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
