//
// Created by 张贺凡 on 2024/11/26.
//

#ifndef LOADABLE_KERNEL_MODULE_HASH_BASED_ROUTING_TABLE_H
#define LOADABLE_KERNEL_MODULE_HASH_BASED_ROUTING_TABLE_H

#include "tools/tools.h"
#include "structure/routing/routing_table_entry.h"
#include "structure/routing/user_space_info.h"

struct HashBasedRoutingTable {
    // 使用的桶的数量
    int bucket_count;
    // 哈希表
    struct hlist_head *bucket_array;
};

struct HashBasedRoutingTable *init_hbrt(int bucket_count);

struct hlist_head *get_bucket_in_hbrt(struct HashBasedRoutingTable *hbrt,
                                      int source_id,
                                      int destination_id);

int routing_entry_equal_judgement(struct RoutingTableEntry *entry, int source_id, int destination_id);

int add_entry_to_hbrt(struct HashBasedRoutingTable *hbrt, struct RoutingTableEntry *routing_table_entry);

int free_hbrt(struct HashBasedRoutingTable *hbrt);

struct RoutingTableEntry *find_sre_in_hbrt(struct HashBasedRoutingTable *hbrt, int source, int destination);



#endif //LOADABLE_KERNEL_MODULE_HASH_BASED_ROUTING_TABLE_H
