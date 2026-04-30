//
// Created by zhf on 2025/12/10.
//

#ifndef PATH_VALIDATION_MODULE_MULTIPATH_RES_H
#define PATH_VALIDATION_MODULE_MULTIPATH_RES_H
#include <linux/list.h>
#include "structure/interface/interface_table.h"
#include "structure/routing/array_based_multipath_table.h"
#include "structure/path_validation_structure.h"
struct MultipathRes {
    int destination;
    // 这里还要取决于选的第一条链路是什么 ?
    struct InterfaceTableEntry* ite;
    // ATLAS 选择的 segment 是什么
    struct AtlasSegment* selected_segment;
    // 选择的映射
    struct OutputInterfaceToPathsMapping* selected_mapping;
    // 还有对应的 segments
    struct list_head* segments;
    // 总的段数
    int number_of_segments;
    // 这些路径之中的最大的路径长度
    int max_path_length;
};

struct MultipathRes* init_mres(int destination, struct InterfaceTableEntry* ite, struct AtlasSegment* segment, struct OutputInterfaceToPathsMapping* selected_mapping, struct list_head* segments, int routing_type, int max_path_length);

struct MultipathRes* construct_mres(struct PathValidationStructure* pvs, int destination, int path_validation_protocol);

void free_mres(struct MultipathRes* mres);
#endif //PATH_VALIDATION_MODULE_MULTIPATH_RES_H
