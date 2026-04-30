//
// Created by zhf on 2025/12/12.
//

#ifndef PATH_VALIDATION_MODULE_ATLAS_VALIDATION_FIELD_H
#define PATH_VALIDATION_MODULE_ATLAS_VALIDATION_FIELD_H
#include "structure/header/opt_header.h"

#define VALIDATION_FIELD_TYPE_PVF 1
#define VALIDATION_FIELD_TYPE_OPV 2
#define VALIDATION_FIELD_TYPE_TAG 3
#define VALIDATION_FIELD_TYPE_END_TAG 4

struct ValidationField{
    unsigned char type; // 验证字段的类型
    unsigned char segment; // 所属的 segment 是谁
    unsigned char removed; // 是否被删除了
    int validation_node_index;  // 节点索引
    char validation_field_desc[100];  // 验证部分的描述
    unsigned char validation_field[OPV_LENGTH]; // 验证部分
    struct list_head list; // 链表
};

struct ActualValidationField{
    unsigned char type; // 验证字段的类型
    unsigned char validation_field[OPV_LENGTH]; // 实际的验证字段
};

struct ValidationField* create_validation_field_copy(struct ValidationField* original);
#endif //PATH_VALIDATION_MODULE_ATLAS_VALIDATION_FIELD_H
