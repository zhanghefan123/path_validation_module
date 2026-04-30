#include "tools/tools.h"
#include "structure/routing/array_based_routing_table.h"

/**
 * array_based_routing_table.c - 以 destination_id 为下标的稠密数组路由表
 *
 * routes[i] 存放目的节点 i 对应的路由表项；未插入前槽位为 NULL。查找与插入均为 O(1)。
 * 各接口对非法参数做防御：越界或 NULL 时查找返回 NULL、插入直接忽略、释放尽量回收已分配内存。
 */

/**
 * init_abrt() - 分配基于数组的路由表并清零各槽位指针
 * @number_of_routes: 槽位个数（须 > 0，与合法 destination_id 上界一致）
 *
 * Return: 成功返回新表指针；number_of_routes 非法或分配失败时返回 NULL。
 */
struct ArrayBasedRoutingTable *init_abrt(int number_of_routes) {
    struct ArrayBasedRoutingTable *abrt;
    int index;

    if (number_of_routes <= 0)
        return NULL;

    abrt = (struct ArrayBasedRoutingTable *)kmalloc(sizeof(struct ArrayBasedRoutingTable), GFP_KERNEL);
    if (!abrt)
        return NULL;

    abrt->number_of_routes = number_of_routes;
    abrt->routes = (struct RoutingTableEntry **)kmalloc(
        sizeof(struct RoutingTableEntry *) * (size_t)number_of_routes, GFP_KERNEL);
    if (!abrt->routes) {
        kfree(abrt);
        return NULL;
    }

    for (index = 0; index < number_of_routes; index++)
        abrt->routes[index] = NULL;
    return abrt;
}

/**
 * free_abrt() - 释放路由表及其中每条已分配的路由表项
 * @abrt: 待释放表；为 NULL 时仅打日志并返回
 *
 * 若 routes 非空且 number_of_routes > 0，则按槽位释放；routes 非空但条数为异常值时
 * 仍释放 routes 指针本身，避免部分初始化或损坏状态导致泄漏。
 */
void free_abrt(struct ArrayBasedRoutingTable *abrt) {
    if (NULL != abrt) {
        int index;

        if (NULL != abrt->routes) {
            if (abrt->number_of_routes > 0) {
                for (index = 0; index < abrt->number_of_routes; index++) {
                    if (NULL != abrt->routes[index]) {
                        free_rte(abrt->routes[index]);
                        abrt->routes[index] = NULL;
                    }
                }
            }
            kfree(abrt->routes);
            abrt->routes = NULL;
        }
        kfree(abrt);
        LOG_WITH_PREFIX("delete array based routing table successfully!");
    } else {
        LOG_WITH_PREFIX("array based routing table is NULL");
    }
}

/**
 * find_rte_in_abrt() - 按目的节点 ID 查找路由表项
 * @abrt: 基于数组的路由表
 * @destination: 目的节点 ID，用作 routes 下标
 *
 * Return: 命中返回指针；abrt/routes 为 NULL、或 destination 越界时返回 NULL。
 */
struct RoutingTableEntry *find_rte_in_abrt(struct ArrayBasedRoutingTable *abrt, int destination) {
    if (!abrt || !abrt->routes)
        return NULL;
    if (destination < 0 || destination >= abrt->number_of_routes)
        return NULL;
    return abrt->routes[destination];
}

/**
 * add_entry_to_abrt() - 将路由表项插入到目的节点 ID 对应槽位
 * @abrt: 基于数组的路由表
 * @rte: 路由表项，使用 rte->destination_id 作为下标
 *
 * 若槽位已有条目且与新条目不同，则先 free_rte 旧项再写入。
 * abrt/routes/rte 为 NULL 或 destination_id 越界时直接返回。
 */
void add_entry_to_abrt(struct ArrayBasedRoutingTable *abrt, struct RoutingTableEntry *rte) {
    struct RoutingTableEntry *old;
    int slot;

    if (!abrt || !abrt->routes || !rte)
        return;

    slot = rte->destination_id;
    if (slot < 0 || slot >= abrt->number_of_routes)
        return;

    old = abrt->routes[slot];
    if (old && old != rte)
        free_rte(old);
    abrt->routes[slot] = rte;
}
