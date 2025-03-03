#include "structure/routing/routing_table_entry.h"

/**
 * 进行路由表项的创建, 分配内存
 * @param bitset_length bitarray 的长度 (unsigned long 为单位)
 * @return
 */
struct RoutingTableEntry *init_routing_table_entry(int effective_bytes) {
    // 为 source_routing_table_entry 分配内存
    struct RoutingTableEntry *source_routing_table_entry = (struct RoutingTableEntry *) kmalloc(sizeof(struct RoutingTableEntry), GFP_KERNEL);
    // 为 bitset 分配内存
    source_routing_table_entry->bitset = (unsigned char *) kmalloc(sizeof(unsigned char) * effective_bytes, GFP_KERNEL);
    // 设置有效字节数
    source_routing_table_entry->effective_bytes = effective_bytes;
    // 返回结果
    return source_routing_table_entry;
}

/**
 * 进行路由表项的释放
 * @param source_routing_table_entry 要释放的路由表项
 */
void free_rte(struct RoutingTableEntry *source_routing_table_entry) {
    if (NULL != source_routing_table_entry) {
        if (NULL != source_routing_table_entry->node_ids) {
            kfree(source_routing_table_entry->node_ids);
            source_routing_table_entry->node_ids = NULL;
        }
        if (NULL != source_routing_table_entry->bitset) {
            kfree(source_routing_table_entry->bitset);
            source_routing_table_entry->bitset = NULL;
        }
        if (NULL != source_routing_table_entry->link_identifiers) {
            kfree(source_routing_table_entry->link_identifiers);
            source_routing_table_entry->link_identifiers = NULL;
        }
        source_routing_table_entry = NULL;
    }
}