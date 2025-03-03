//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
#define LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
#include <net/ip.h>

// 1. 接口表项相关内容
// ----------------------------------------------------------------------------------------------
struct InterfaceTableEntry {
    int index;
    int link_identifier; // 链路标识
    struct net_device *interface; // 对应的接口
    __be32 peer_ip_address; // 对侧接口的 ip 地址
    unsigned char* bitset; // 将这个标识插入之后的布隆过滤器
};
// ----------------------------------------------------------------------------------------------

// 2. 基于数组的接口表相关内容
// ----------------------------------------------------------------------------------------------
struct ArrayBasedInterfaceTable{
    // 总的接口的数量
    int number_of_interfaces;
    // 所有的接口
    struct InterfaceTableEntry** interfaces;
};
struct InterfaceTableEntry* init_ite(int index, int effective_bytes);
struct ArrayBasedInterfaceTable* init_abit(int number_of_interfaces);
void free_abit(struct ArrayBasedInterfaceTable* abit);
struct InterfaceTableEntry* find_ite_in_abit(struct ArrayBasedInterfaceTable* abit, int link_identifier);
void add_ite_to_abit(struct ArrayBasedInterfaceTable* abit, struct InterfaceTableEntry* ite);
void free_ite(struct InterfaceTableEntry* entry);
// ----------------------------------------------------------------------------------------------

#endif //LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
