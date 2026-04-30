//
// Created by zhf on 2025/12/12.
//

#ifndef PATH_VALIDATION_MODULE_ATLAS_SEGMENT_H
#define PATH_VALIDATION_MODULE_ATLAS_SEGMENT_H
#include <linux/list.h>
#include "structure/interface/interface_table.h"
struct AtlasSegment{
    int self_position_in_the_segment; // 自己在这个 segment 之中所处的位置
    int destination; // 所属的是到哪个目的节点的子路径
    int id; // 索引 (这个并没有进行初始化)
    int parent_id;
    int depth; // 段深度
    int length; // 长度
    int *array; // 变长数组
    int decision_point; // 进行决策的节点就是源节点
    struct InterfaceTableEntry* ite; //  出接口
    struct list_head list; // 链表节点
    struct list_head tmp; // 临时链表节点
    struct list_head tmp1; // 临时链表节点1
    struct hlist_node pointer; // 哈希表指针
};

void free_atlas_segment(struct AtlasSegment* atlas_segment);
#endif //PATH_VALIDATION_MODULE_ATLAS_SEGMENT_H
