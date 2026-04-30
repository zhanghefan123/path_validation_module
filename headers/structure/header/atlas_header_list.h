//
// Created by zhf on 2025/12/12.
//

#ifndef PATH_VALIDATION_MODULE_ATLAS_HEADER_LIST_H
#define PATH_VALIDATION_MODULE_ATLAS_HEADER_LIST_H
#include "structure/header/atlas_header.h"
struct HeaderList{
    int source_node_index; // 源节点的名字
    int destination_node_index; // 目的节点的名字
    int depth; // 深度
    int start_tag; // 起始标签
    int parent_id; // 父亲的 id
    struct list_head* validation_field_list;  // 验证字段列表 OPV
    int end_tag; // 结束标签
    struct list_head list;
};

struct HeaderConstructionResult{
    struct list_head* all_header_list;
    int max_depth; // 最大深度
};

struct ValidationField*  judge_should_insert(struct HeaderList* header_list_with_depth, struct HeaderList* header_list_with_depth_minus_one);
void free_header_list(struct HeaderList* header_list);
struct HeaderList* create_header_list_from_segment(struct AtlasSegment* segment,  unsigned char* static_fields_hash, struct shash_desc* hmac_api, int* mac_count);
struct list_head* integrate(struct list_head* all_headers_lists, int depth);
void find_and_insert(struct HeaderList* from, struct HeaderList* to, struct ValidationField* validation_field);
void remove_validation_field_list(struct list_head* validation_field_list);
void remove_header_list(struct list_head* all_header_list, struct HeaderList* delete_header_list);
void remove_all_header_list(struct list_head* all_header_list);
void print_all_header_lists(struct list_head* all_header_list);
void print_header_list(struct HeaderList* header_list);
void print_validation_list(struct list_head* validation_list);
#endif //PATH_VALIDATION_MODULE_ATLAS_HEADER_LIST_H
