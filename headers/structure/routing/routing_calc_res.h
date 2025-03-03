//
// Created by 张贺凡 on 2024/11/26.
//

#ifndef LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H
#define LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H

#include <net/ip.h>
#include "structure/crypto/bloom_filter.h"
#include "structure/routing/user_space_info.h"
#include "structure/path_validation_structure.h"

// 1. 路由计算结果
struct RoutingCalcRes {
    int source;
    unsigned char *bitset; // 结果布隆过滤器
    struct InterfaceTableEntry *ite; // 出接口
    struct UserSpaceInfo *user_space_info; // 目的信息
    int number_of_routes; // 路由条目数量
    struct RoutingTableEntry** rtes; // 当为 ICING, OPT, SELIR 的时候返回的结果
};

// 2. 初始化计算结果
struct RoutingCalcRes *init_rcr(int source, struct UserSpaceInfo *user_space_info, int bitset_length, int protocol);

// 3. 释放路由计算结果
void free_rcr(struct RoutingCalcRes *route_calculation_result);

// 4. 根据 dest_and_proto_info 创建
struct RoutingCalcRes *construct_rcr_with_user_space_info(struct PathValidationStructure *pvs, struct UserSpaceInfo *user_space_info, int source);

// 5. 基于 abrt 创建
struct RoutingCalcRes *construct_rcr_with_user_space_info_under_abrt(struct UserSpaceInfo *user_space_info,
                                                                     struct ArrayBasedRoutingTable* abrt,
                                                                     int source,
                                                                     int bitset_length);

// 6. 基于 hbrt 创建
struct RoutingCalcRes *construct_rcr_with_dest_info_under_hbrt(struct UserSpaceInfo *user_space_info,
                                                               struct HashBasedRoutingTable* hbrt,
                                                               int source,
                                                               int bitset_length);

#endif //LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H
