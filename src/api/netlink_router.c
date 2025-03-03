#include "api/netlink_router.h"
#include "api/netlink_handler.h"

/**
 * 定义属性和类型的一个映射关系
 */
struct nla_policy attr_type_mapping[EXMPL_NLA_MAX] = {
        [EXMPL_NLA_DATA] = {.type = NLA_NUL_STRING},
        [EXMPL_NLA_LEN] = {.type = NLA_U32}
};


/**
 * netlink 的启动方法
 * 无参数
 * 无返回值
 */
void netlink_server_init(void){
    genl_register_family(&exmpl_genl_family);
}

/**
 * netlink 的结束方法
 * 无参数
 * 无返回值
 */
void netlink_server_exit(void){
    genl_unregister_family(&exmpl_genl_family);
}

/**
 * 命令和实际的函数的映射
 */
const struct genl_ops exmpl_gnl_ops_echo[] = {
        // 接收到用户空间下发的路由条目插入命令，绑定相应的 callback function index=1
         {
                 .cmd = CMD_ECHO,
                 .policy = attr_type_mapping,
                 .doit = netlink_echo_handler,
         },
         {
                 .cmd = CMD_SET_NODE_ID,
                 .policy = attr_type_mapping,
                 .doit = netlink_set_node_id_handler,
         },
         {
                .cmd = CMD_INIT_ROUTING_AND_FORWARDING_TABLE,
                .policy = attr_type_mapping,
                .doit = netlink_init_routing_and_forwarding_table_handler,
         },
         {
                .cmd = CMD_INIT_SELIR,
                .policy = attr_type_mapping,
                .doit = netlink_init_selir,
         },
         {
                .cmd = CMD_INIT_BLOOM_FILTER,
                .policy = attr_type_mapping,
                .doit = netlink_init_bloom_filter_handler,
         },
         {
                 .cmd = CMD_INSERT_INTERFACE_TABLE_ENTRY,
                 .policy = attr_type_mapping,
                 .doit = netlink_insert_interface_table_entry_handler,
         },
         {
                .cmd = CMD_INSERT_ROUTING_TABLE_ENTRY,
                .policy = attr_type_mapping,
                .doit = netlink_insert_routing_table_entry_handler,
         },
};

/**
 * 定义generate_netlink协议的内容
 */
struct genl_family exmpl_genl_family __ro_after_init = {
        .name = "EXMPL_GENL",  // 需要在用户空间使用
        .version = VERSION_NR,  // 版本号
        .maxattr = EXMPL_NLA_MAX - 1, // 最大属性数量
        .module = THIS_MODULE, // 当前模块
        .ops = exmpl_gnl_ops_echo, // 命令和实际的函数的映射
        .n_ops = ARRAY_SIZE(exmpl_gnl_ops_echo), // 映射数量
        .netnsok = true // 一定需要添加这个从而可以让网络命名空间生效
};