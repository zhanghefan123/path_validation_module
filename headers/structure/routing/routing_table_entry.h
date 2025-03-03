//
// Created by 张贺凡 on 2024/11/26.
//

#ifndef LOADABLE_KERNEL_MODULE_ROUTING_TABLE_ENTRY_H
#define LOADABLE_KERNEL_MODULE_ROUTING_TABLE_ENTRY_H
#include <net/ip.h>
#include "structure/interface/interface_table.h"
// 1. 路由表项
struct RoutingTableEntry {
    int source_id;       // 源节点的 id
    int destination_id;  // 目的节点的 id
    int path_length;  // 路径的长度
    int *node_ids;       // 节点序列
    unsigned char *bitset; // 插入 link_identifiers 所对应的 bitset
    int *link_identifiers; // 到目的节点的链路表示序列
    struct InterfaceTableEntry *output_interface; // 出接口所对应的接口表项
    u32 effective_bytes; // bitset 所对应的有效的字节数
    struct hlist_node pointer; // 指针指向的是下一个路由条目
};

// 2. 初始化源路由表项
struct RoutingTableEntry *init_routing_table_entry(int effective_bytes);

// 3. 释放源路由表项
void free_rte(struct RoutingTableEntry *source_routing_table_entry);

#endif //LOADABLE_KERNEL_MODULE_ROUTING_TABLE_ENTRY_H
