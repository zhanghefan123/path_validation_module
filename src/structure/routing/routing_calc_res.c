#include "structure/routing/routing_calc_res.h"
#include "structure/routing/variables.h"
#include "api/test.h"


/**
 * 进行路由计算返回结果的创建
 * @param destination_info 目的信息
 * @param bf_effective_bytes 布隆过滤器的有效字节数量
 * @param bitset_length 字节数组长度
 * @param protocol 协议
 * @param number_of_destinations 目的节点的数量
 * @return
 */
struct RoutingCalcRes *init_rcr(int source, struct UserSpaceInfo *destination_info, int bitset_length, int protocol) {
    // 判断协议
    if (LIR_VERSION_NUMBER == protocol) {
        struct RoutingCalcRes *route_calculation_result = (struct RoutingCalcRes *) (kmalloc(
                sizeof(struct RoutingCalcRes), GFP_KERNEL));
        route_calculation_result->bitset = (unsigned char *) (kmalloc(bitset_length, GFP_KERNEL));
        route_calculation_result->ite = NULL;
        route_calculation_result->source = source;
        route_calculation_result->user_space_info = destination_info;
        route_calculation_result->number_of_routes = 0;
        route_calculation_result->rtes = NULL;
        return route_calculation_result;
    } else {
        struct RoutingCalcRes *route_calculation_result = (struct RoutingCalcRes *) (kmalloc(
                sizeof(struct RoutingCalcRes), GFP_KERNEL));
        route_calculation_result->bitset = NULL;
        route_calculation_result->ite = NULL;
        route_calculation_result->source = source;
        route_calculation_result->user_space_info = destination_info;
        route_calculation_result->number_of_routes = destination_info->number_of_destinations;
        route_calculation_result->rtes = (struct RoutingTableEntry **) (kmalloc(
                sizeof(struct RoutingTableEntry *) * destination_info->number_of_destinations, GFP_KERNEL));
        return route_calculation_result;
    }
}

/**
 * 进行 route_calculation_result 的释放
 * @param route_calculation_result
 */
void free_rcr(struct RoutingCalcRes *route_calculation_result) {
    if (NULL != route_calculation_result) {
        // 进行 bitsets 的释放
        if (NULL != route_calculation_result->bitset) {
            kfree(route_calculation_result->bitset);
            route_calculation_result->bitset = NULL;
        }
        if (NULL != route_calculation_result->rtes) {
            kfree(route_calculation_result->rtes);
            route_calculation_result->rtes = NULL;
        }
        // 进行 RoutingCalcRes 结构占用的内存的释放
        kfree(route_calculation_result);
        route_calculation_result = NULL;
    }
}


/**
 *
 * @param pvs
 * @param user_space_info
 * @param source
 * @return
 */
struct RoutingCalcRes *construct_rcr_with_user_space_info(struct PathValidationStructure *pvs,
                                                          struct UserSpaceInfo *user_space_info,
                                                          int source) {
    struct RoutingCalcRes *rcr;
    if (ARRAY_BASED_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        rcr = construct_rcr_with_user_space_info_under_abrt(user_space_info, pvs->abrt, source,
                                                            (int) (pvs->bloom_filter->bf_effective_bytes));
    } else if (HASH_BASED_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        rcr = construct_rcr_with_dest_info_under_hbrt(user_space_info, pvs->hbrt, source,
                                                      (int) (pvs->bloom_filter->bf_effective_bytes));
    } else {
        LOG_WITH_PREFIX("unsupported routing table type");
        return NULL;
    }
    return rcr;
}

/**
 * 根据目的信息, 创建路由计算结果
 * @param user_space_info 目的和协议信息
 * @param abrt 基于数组的路由表
 * @param source 源节点
 * @param bitset_length 字节数组长度
 * @return
 */
struct RoutingCalcRes *construct_rcr_with_user_space_info_under_abrt(struct UserSpaceInfo *user_space_info,
                                                                     struct ArrayBasedRoutingTable *abrt,
                                                                     int source,
                                                                     int bitset_length) {

    if (1 != user_space_info->number_of_destinations) {
        // 1. 因为 abrt 只能支持单播, 如果长度大于0, 那么返回 NULL
        return NULL;
    } else {
        // 2. 因为
        // 创建 rcr
        struct RoutingCalcRes *rcr = init_rcr(source, user_space_info, bitset_length,
                                              user_space_info->path_validation_protocol);
        // 只允许单个目的节点
        struct RoutingTableEntry *rte = find_rte_in_abrt(abrt, user_space_info->destinations[0]);
        // 设置出接口
        rcr->ite->interface = rte->output_interface->interface;
        // 如果在这个结构下, 只允许单个目的地址
        if (LIR_VERSION_NUMBER == user_space_info->path_validation_protocol) {
            memory_or(rcr->bitset, rte->bitset, (int) (bitset_length)); // 进行按位或运算
        } else if (ICING_VERSION_NUMBER == user_space_info->path_validation_protocol) {
            rcr->rtes[0] = rte;  // 因为要进行后续的
        } else if (OPT_VERSION_NUMBER == user_space_info->path_validation_protocol) {
            rcr->rtes[0] = rte;
        } else if ((SELIR_VERSION_NUMBER == user_space_info->path_validation_protocol) ||
                   (FAST_SELIR_VERSION_NUMBER == user_space_info->path_validation_protocol)) {
            rcr->rtes[0] = rte;
        } else {
            LOG_WITH_PREFIX("unsupported protocol");
        }
        return rcr;
    }
}

/**
 *
 * @param hbrt 基于哈希的路由表
 * @param user_space_info 目的节点信息
 * @param bf_effective_bytes bf 的有效字节数
 * @param source 源节点 id
 * @param number_of_interfaces 接口的数量
 * @return
 */
struct RoutingCalcRes *construct_rcr_with_dest_info_under_hbrt(struct UserSpaceInfo *user_space_info,
                                                               struct HashBasedRoutingTable *hbrt,
                                                               int source,
                                                               int bitset_length) {
    // 1.索引
    int index;

    // 2.创建 rcr
    struct RoutingCalcRes *rcr = init_rcr(source, user_space_info, bitset_length,
                                          user_space_info->path_validation_protocol);

    // 3. 根据不同情况进行处理
    if (LIR_VERSION_NUMBER == user_space_info->path_validation_protocol) {
        // 首先找到主节点
        int primaryNodeId = user_space_info->destinations[0];
        // 找到到主节点的路由
        struct RoutingTableEntry *source_to_primary = find_sre_in_hbrt(hbrt, source, primaryNodeId);
        // 更新出接口和 bitset
        rcr->ite = source_to_primary->output_interface;
        memory_or(rcr->bitset, source_to_primary->bitset, (int) (bitset_length));
        // 接着找到主节点到其他节点的路由
        for (index = 1; index < user_space_info->number_of_destinations; index++) {
            int otherNodeId = user_space_info->destinations[index];
            struct RoutingTableEntry *primary_to_other = find_sre_in_hbrt(hbrt,
                                                                          primaryNodeId,
                                                                          otherNodeId);
            // 进行 bitset 的更新
            memory_or(rcr->bitset, primary_to_other->bitset, (int) (bitset_length));
        }
    } else if (ICING_VERSION_NUMBER == user_space_info->path_validation_protocol) {
        if (1 != user_space_info->number_of_destinations) {
            LOG_WITH_PREFIX("icing only support unicast");
            return NULL;
        } else {
            int destination = user_space_info->destinations[0];
            struct RoutingTableEntry *rte = find_sre_in_hbrt(hbrt, source, destination);
            rcr->rtes[0] = rte;
            rcr->ite = rte->output_interface;
        }
    } else if (OPT_VERSION_NUMBER == user_space_info->path_validation_protocol) {
        if (1 != user_space_info->number_of_destinations) {
            LOG_WITH_PREFIX("opt only support unicast");
            return NULL;
        } else {
            int destination = user_space_info->destinations[0];
            struct RoutingTableEntry *rte = find_sre_in_hbrt(hbrt, source, destination);
            rcr->rtes[0] = rte;
            rcr->ite = rte->output_interface;
        }
    } else if (SELIR_VERSION_NUMBER == user_space_info->path_validation_protocol) { // SELiR 的单播版本
        // 拿到唯一的目的节点
        int only_destination = user_space_info->destinations[0];
        // 进行路由表的查找
        struct RoutingTableEntry *only_route = find_sre_in_hbrt(hbrt, source, only_destination);
        // 更新出接口
        rcr->ite = only_route->output_interface;
        // 添加路由
        rcr->rtes[0] = only_route;
    } else if (FAST_SELIR_VERSION_NUMBER == user_space_info->path_validation_protocol) {
        // 拿到唯一的目的节点
        int only_destination = user_space_info->destinations[0];
        // 进行路由表的查找
        struct RoutingTableEntry *only_route = find_sre_in_hbrt(hbrt, source, only_destination);
        // 更新出接口
        rcr->ite = only_route->output_interface;
        // 添加路由
        rcr->rtes[0] = only_route;
    } else if (MULTICAST_SELIR_VERSION_NUMBER == user_space_info->path_validation_protocol) {
        // 首先找到主节点
        int primaryNodeId = user_space_info->destinations[0];
        // 找到到主节点的路由
        struct RoutingTableEntry *source_to_primary = find_sre_in_hbrt(hbrt, source, primaryNodeId);
        // 更新出接口
        rcr->ite = source_to_primary->output_interface;
        // 进行路由条目的更新
        rcr->rtes[0] = source_to_primary;
        // 利用到主节点的路由形成
        for (index = 1; index < user_space_info->number_of_destinations; index++) {
            int otherNodeId = user_space_info->destinations[index];
            struct RoutingTableEntry *primary_to_other = find_sre_in_hbrt(hbrt,
                                                                          primaryNodeId,
                                                                          otherNodeId);
            // 进行路由条目的更新
            rcr->rtes[index] = primary_to_other;
        }
    } else {
        LOG_WITH_PREFIX("unsupported protocol");
    }

    // 3.使用基于主节点的方式
    // -----------------------------------------------------------------------------------------

    // 6. 进行结果的返回
    return rcr;
}

/*
 * Incompatible pointer types passing 'struct PathValidationStructure *' to parameter of type 'struct PathValidationStructure *'
 */