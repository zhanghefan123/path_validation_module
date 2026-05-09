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
    CMD_USERSPACE_TO_KERNEL_UNSPEC, // 0
    CMD_ECHO, // 1. 用来进行消息回显的
    CMD_SET_NODE_ID, // 2. 用来设置本节点的 id
    CMD_INIT_ROUTING_TABLE, // 3. 初始化路由表
    CMD_INIT_FORWARDING_TABLE, // 4. 初始化接口表
    CMD_INIT_MULTIPATH_TABLE, // 5. 初始化多路径表
    CMD_INIT_SELIR,  // 6. 初始化 selir 数据结构
    CMD_INIT_BLOOM_FILTER, // 7. 初始化布隆过滤器
    CMD_MODIFY_BLOOM_FILTER, // 8. 进行布隆过滤器参数的修改
    CMD_INSERT_INTERFACE_TABLE_ENTRY, // 9. 进行接口表条目的插入 (注意要首先进行接口表条目的插入, 因为在构建路由表的时候需要利用到接口表)
    CMD_INSERT_ROUTING_TABLE_ENTRY, // 10. 进行路由表条目的插入
    CMD_INSERT_DEST_ROUTING_TABLE_ENTRY,  // 11. 进行目的路由条目的插入
    CMD_SET_LIR_SINGLE_TIME_ENCODING_COUNT, // 12. 设置 LiR 单词插入的元素的个数
    CMD_PRINT_ROUTING_TABLE_ENTRIES, // 13. 释放网络命名空间之中的内存
    CMD_SOURCE_INSERT_SEGMENT, // 14. 进行 segment 的插入, 插入到链表之中
    CMD_INTERMEDIATE_INSERT_SEGMENT, // 15. 中间节点进行 segment 的插入, 插入到哈希表之中
    CMD_CLEAR_SEGMENT_LIST, // 16. 进行 segment list 的删除
    CMD_INSERT_OUTPUT_LINK_IDENTIFIERS, // 17. 配合多路径实现出接口的记录
    CMD_INSERT_RELATIONSHIP_BETWEEN_NEXT_NODE_ID_AND_PATHS, // 18. 绑定下一个节点id和 path的关系
    CMD_SET_SEC_PATH_MAB_ROUTE, // 19. 获取用户空间下发的路径
    CMD_RESET_SEC_PATH_MAB_ROUTE, // 20. 重置路径
    CMD_SET_ROUTER_TYPE, // 21. 进行路由器类型的设置 (可能有普通的路由器和路径验证路由器)
    CMD_SET_SEC_PATH_MAB_TYPE,  // 22. 进行 sec_path_mab 策略的设置
    CMD_SET_MALICIOUS_PARAMS, // 23. 进行恶意参数的设置
    CMD_RETRIEVE_KERNEL_INFORMATION, // 24. 进行需要的 counters 和 acks 的获取
    CMD_SET_SCHDULED_MALICIOUS_PARAMS, // 25. 进行定时的恶意参数设置
    CMD_SET_MIN_ACK_FOR_RTT_ESTIMATION, // 26 设置 RTT
    CMD_START_SEC_PATH_MAB_SYNC,  // 27. 同步 (使用内核作为时间戳)
};

#define VERSION_NR 1
extern struct genl_family exmpl_genl_family;
extern const struct genl_ops exmpl_gnl_ops_echo[];
extern struct nla_policy attr_type_mapping[EXMPL_NLA_MAX];

#endif //LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
