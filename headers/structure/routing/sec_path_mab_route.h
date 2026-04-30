//
// Created by zhf on 2026/3/27.
//

#ifndef PATH_VALIDATION_MODULE_SEC_PATH_MAB_ROUTER_H
#define PATH_VALIDATION_MODULE_SEC_PATH_MAB_ROUTER_H
#include <net/ip.h>

// 采样序列
struct SampleSequence {
    int sequence_length;
    int current_index;
    unsigned char *actual_sequence;
};

// 每次由用户空间下发一条路由
struct SecPathMabRoute{
    int source_id; // 源节点 id
    int destination_id; // 目的节点 id
    int number_of_link_identifiers; // 逐跳路径长度
    int* link_identifiers; // 链路标识序列 (用来进行逐跳的转发)
    int number_of_sample_nodes; // 采样的节点的数量
    int* sample_node_ids; // 源, 目的, 以及各个支持路径验证功能的路由器。
    struct InterfaceTableEntry* ite; // 出接口
    struct SampleSequence* sample_sequence; // 采样序列
};



// 测试拓扑: a -----N1-----> b -----N2-----> c
// 普通节点:  N1 N2
// 链路标识:  link_id1, link_id2, link_id3, link_id4
// 采样节点标识:   b, c
// 消息格式: source_id, destination_id, link_identifiers, link_id1, link_id2, link_id3, link_id4, abs_path_length, b, c, batch_size

void free_sec_path_mab_route(struct SecPathMabRoute* route);

struct SampleSequence* generate_sequence(int number_of_sample_nodes, int sequence_length, int* sample_counts);

void free_sequence(struct SampleSequence* sample_sequence);

void reset_sec_path_mab_route_sequence(struct SecPathMabRoute* route, int sequence_length, int* sample_counts);

void test_generate_sample_sequence(void);

#endif //PATH_VALIDATION_MODULE_SEC_PATH_MAB_ROUTER_H
