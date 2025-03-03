//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
#define LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
#include <net/genetlink.h>

void netlink_server_init(void); // netlink server 初始化

void netlink_server_exit(void); // netlink server 退出


/**
 * 消息的类型，用户空间同样需要定义相应的代码
 */
enum {
    EXMPL_NLA_UNSPEC, // 未指定
    EXMPL_NLA_DATA, // 数据部分
    EXMPL_NLA_LEN, // 数据的长度
    EXMPL_NLA_MAX,  // 最大的数量
};

/**
 * 命令的类型, 用户空间同样需要定义相应的命令类型
 */

enum {
    CMD_UNSPEC,
    CMD_ECHO, // 1. 用来进行消息回显的
    CMD_SET_NODE_ID, // 2. 用来设置本节点的 id
    CMD_INIT_ROUTING_AND_FORWARDING_TABLE, // 2. 初始化路由表和接口表
    CMD_INIT_SELIR,  // 3. 初始化 selir 数据结构
    CMD_INIT_BLOOM_FILTER, // 4. 初始化布隆过滤器
    CMD_INSERT_INTERFACE_TABLE_ENTRY, // 5. 进行接口表条目的插入 (注意要首先进行接口表条目的插入, 因为在构建路由表的时候需要利用到接口表)
    CMD_INSERT_ROUTING_TABLE_ENTRY, // 6. 进行路由表条目的插入

};

#define VERSION_NR 1
extern struct genl_family exmpl_genl_family;
extern const struct genl_ops exmpl_gnl_ops_echo[];
extern struct nla_policy attr_type_mapping[EXMPL_NLA_MAX];

#endif //LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
