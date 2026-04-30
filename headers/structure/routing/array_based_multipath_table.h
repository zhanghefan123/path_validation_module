//
// Created by zhf on 2025/12/9.
//

#ifndef PATH_VALIDATION_MODULE_ARRAY_BASED_MULTIPATH_TABLE_H
#define PATH_VALIDATION_MODULE_ARRAY_BASED_MULTIPATH_TABLE_H
#include <net/ip.h>
#include "structure/interface/interface_table.h"
#include "structure/header/atlas_segment.h"
#include "structure/routing/routing_table_entry.h"


#define ROUTING_TYPE_ATLAS 1
#define ROUTING_TYPE_MULTIPATH_SELIR 2

struct OutputLinkIdentifiers {
    int number;
    int count;
    int *link_identifiers;
};

struct OutputInterfaceToPathsMapping {
    struct InterfaceTableEntry* ite;
    int path_ids_count;
    unsigned char* path_ids;
    unsigned char* bit_set;
};

struct ArrayBasedMultipathTable{
    // 进行计数
    int packet_send_count;
    // 总共的可能的目的节点数量
    int array_size;
    // 一个 list_head 存储到某个 destination 的所有的 segments (atlas 源节点使用)
    struct list_head* multipaths;
    // 每个 output_link_identifier[index] 存储的是所有的前往 index 这个目的节点的 link_identifiers
    struct OutputLinkIdentifiers* output_link_identifiers;

    // -------------------------- 记录 output interface --------------------------
    struct OutputInterfaceToPathsMapping** output_interface_to_path_mappings;
    // 记录 output_segments 的数值
    int number_of_interface_to_path_mappings;
    // 记录当前的 index
    int interface_to_path_mapping_index;
    // 路径的数量
    int number_of_paths;
    // -------------------------- 记录 output interface --------------------------


    // 存储最大的路径长度
    int max_path_length;
    // 路由的类型 (可能是 atlas 或者 multipath_selir)
    int routing_type;
    // segment 的总数 适用于 atlas
    int segments_count;
    // 路由条目的总数  适用于 multipath selir
    int routing_entries_count;
    // 中间节点使用
    int bucket_count;
    struct hlist_head* bucket_array;
};

struct ArrayBasedMultipathTable * init_abpt(int number_of_destinations, int bucket_count, int multipath_routing_type, int number_of_output_segments, int number_of_paths);

void free_abpt(struct ArrayBasedMultipathTable* abpt);

void delete_segment_list(struct list_head* head);

void delete_paths_list(struct list_head* head);

struct list_head* find_segments_or_paths_in_abpt(struct ArrayBasedMultipathTable* abpt, int destination);

struct AtlasSegment* find_output_interface_in_abpt_for_atlas(struct ArrayBasedMultipathTable* abpt, int node_id, int destination);

struct OutputInterfaceToPathsMapping* find_output_interface_to_paths_mapping(struct ArrayBasedMultipathTable* abpt);

struct InterfaceTableEntry* find_output_interface_in_abpt_for_multipath_selir(struct ArrayBasedMultipathTable* abpt, struct ArrayBasedInterfaceTable* abit, int destination);

// 哈希表相关内容
u64 calculate_hash_based_on_segment_id(int destination, int segment_id);

u64 calculate_hash_based_on_length_of_path(int length_of_path);

struct hlist_head* atlas_get_bucket_in_abpt(struct ArrayBasedMultipathTable* abpt, int destination, int segment_id);

struct hlist_head* multipath_selir_get_bucket_in_abpt(struct ArrayBasedMultipathTable* abpt, int length_of_path);

int atlas_segment_equal_judgement(struct AtlasSegment* atlas_segment, int destination, int segment_id);

int multipath_selir_routing_entry_equal_judegement(struct RoutingTableEntry* rte, const int* node_identifiers, int count);

void atlas_add_entry_to_abpt_in_chain_format(struct ArrayBasedMultipathTable* abpt, struct AtlasSegment* atlas_segment);

int atlas_add_entry_to_abpt_in_hash_format(struct ArrayBasedMultipathTable* abpt, struct AtlasSegment* atlasSegment);

struct AtlasSegment* find_atlas_segment_in_abpt(struct ArrayBasedMultipathTable* abpt, int destination, int segment_id);

struct RoutingTableEntry* find_rte_in_abpt(struct ArrayBasedMultipathTable* abpt, int* link_identifiers, int path_length);

struct AtlasSegment* source_insert_atlas_segment(char* receive_buffer, struct ArrayBasedMultipathTable* abpt);

struct AtlasSegment* intermediate_insert_atlas_segment(char* receive_buffer, struct ArrayBasedMultipathTable* abpt);

struct AtlasSegment* create_copy_of_atlas_segment(struct AtlasSegment* atlas_segment);

void add_routing_table_entry_to_abpt_in_chain_format(struct ArrayBasedMultipathTable* abpt, struct RoutingTableEntry* rte);

int add_routing_table_entry_to_abpt_in_hash_format(struct ArrayBasedMultipathTable* abpt, struct RoutingTableEntry* rte);

#endif //PATH_VALIDATION_MODULE_ARRAY_BASED_MULTIPATH_TABLE_H
