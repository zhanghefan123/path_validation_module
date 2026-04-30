#include "api/netlink_router.h"
#include "api/netlink_handler.h"

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
                .cmd = CMD_INIT_ROUTING_TABLE,
                .policy = attr_type_mapping,
                .doit = netlink_init_routing_table,
        }, {
                .cmd = CMD_INIT_FORWARDING_TABLE,
                .policy = attr_type_mapping,
                .doit = netlink_init_interface_table,
        },
        {
                .cmd = CMD_INIT_MULTIPATH_TABLE,
                .policy = attr_type_mapping,
                .doit = netlink_init_array_based_multipath_table_handler,
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
                .cmd = CMD_MODIFY_BLOOM_FILTER,
                .policy = attr_type_mapping,
                .doit = netlink_modify_bloom_filter_handler,
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
        },{
                .cmd = CMD_INSERT_DEST_ROUTING_TABLE_ENTRY,
                .policy = attr_type_mapping,
                .doit = netlink_insert_dest_routing_table_entry_handler,
        },
        {
                .cmd = CMD_SET_LIR_SINGLE_TIME_ENCODING_COUNT,
                .policy = attr_type_mapping,
                .doit = netlink_set_lir_single_time_encoding_count_handler,
        },
        {
                .cmd = CMD_PRINT_ROUTING_TABLE_ENTRIES,
                .policy = attr_type_mapping,
                .doit = print_routing_table_entries,
        },
        {
                .cmd = CMD_SOURCE_INSERT_SEGMENT,
                .policy = attr_type_mapping,
                .doit = netlink_source_insert_segment_handler,
        },
        {
                .cmd = CMD_INTERMEDIATE_INSERT_SEGMENT,
                .policy = attr_type_mapping,
                .doit = netlink_intermediate_insert_segment_handler,
        },
        {
                .cmd = CMD_CLEAR_SEGMENT_LIST,
                .policy = attr_type_mapping,
                .doit = netlink_clear_segment_list,
        },
        {
                .cmd = CMD_INSERT_OUTPUT_LINK_IDENTIFIERS,
                .policy = attr_type_mapping,
                .doit = netlink_insert_output_link_identifiers,
        },
        {
                .cmd = CMD_INSERT_RELATIONSHIP_BETWEEN_NEXT_NODE_ID_AND_PATHS,
                .policy = attr_type_mapping,
                .doit = netlink_insert_relationship_between_next_node_id_and_paths,
        },
         {
                .cmd = CMD_SET_SEC_PATH_MAB_ROUTE,
                .policy = attr_type_mapping,
                .doit = netlink_set_sec_path_mab_route,
        },
        {
                .cmd = CMD_RESET_SEC_PATH_MAB_ROUTE,
                .policy = attr_type_mapping,
                .doit = netlink_reset_sec_path_mab_route,
        },
        {
                .cmd = CMD_SET_ROUTER_TYPE,
                .policy = attr_type_mapping,
                .doit = netlink_set_router_type,
        },
        {
                .cmd = CMD_SET_SEC_PATH_MAB_TYPE,
                .policy = attr_type_mapping,
                .doit = netlink_set_sec_path_mab_type,
        },
        {
                .cmd = CMD_SET_MALICIOUS_PARAMS,
                .policy = attr_type_mapping,
                .doit = netlink_set_router_malicious_parameters,
        }, {
                .cmd = CMD_RETRIEVE_KERNEL_INFORMATION,
                .policy = attr_type_mapping,
                .doit = netlink_retrieve_kernel_information,
        }, {
                .cmd = CMD_SET_SCHDULED_MALICIOUS_PARAMS,
                .policy = attr_type_mapping,
                .doit = netlink_set_scheduled_malicious_params,
        },{
            .cmd = CMD_SET_MIN_ACK_FOR_RTT_ESTIMATION,
            .policy = attr_type_mapping,
            .doit = netlink_set_min_ack_for_rtt_estimation,
        },
};

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
void netlink_server_init(void) {
    genl_register_family(&exmpl_genl_family);
}

/**
 * netlink 的结束方法
 * 无参数
 * 无返回值
 */
void netlink_server_exit(void) {
    genl_unregister_family(&exmpl_genl_family);
}


/**
 * 定义generate_netlink协议的内容
 */
struct genl_family exmpl_genl_family __ro_after_init = {
        .id = 123,
        .name = "EXMPL_GENL",  // 需要在用户空间使用 (这个改成别的就不好用了是为什么)
        .version = VERSION_NR,  // 版本号
        .maxattr = EXMPL_NLA_MAX - 1, // 最大属性数量
        .module = THIS_MODULE, // 当前模块
        .ops = exmpl_gnl_ops_echo, // 命令和实际的函数的映射
        .n_ops = ARRAY_SIZE(exmpl_gnl_ops_echo), // 映射数量
        .netnsok = true // 一定需要添加这个从而可以让网络命名空间生效
};