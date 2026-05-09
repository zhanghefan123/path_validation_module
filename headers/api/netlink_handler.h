//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
#define LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
#include <net/sock.h>
#include <net/genetlink.h>
#define MAX_NETLINK_MESSAGE_SIZE 4096
int recv_message_copy(struct genl_info* info, char* buffer, size_t buffer_size);
char* recv_message(struct genl_info* info);
int send_reply(char* response_buffer, struct genl_info* info);
int netlink_echo_handler(struct sk_buff* request, struct genl_info* info);
int netlink_set_node_id_handler(struct sk_buff* request, struct genl_info* info);
int netlink_init_routing_table(struct sk_buff* request, struct genl_info* info);
int netlink_init_interface_table(struct sk_buff* request, struct genl_info* info);
int netlink_init_array_based_multipath_table_handler(struct sk_buff* request, struct genl_info* info);
int netlink_init_selir(struct sk_buff* request, struct genl_info* info);
int netlink_init_bloom_filter_handler(struct sk_buff* request, struct genl_info* info);
int netlink_modify_bloom_filter_handler(struct sk_buff* request, struct genl_info* info);
int netlink_clear_segment_list(struct sk_buff* request, struct genl_info* info);
int netlink_insert_output_link_identifiers(struct sk_buff* request, struct genl_info* info);
int netlink_insert_relationship_between_next_node_id_and_paths(struct sk_buff* request, struct genl_info* info);
int netlink_source_insert_segment_handler(struct sk_buff* request, struct genl_info* info);
int netlink_intermediate_insert_segment_handler(struct sk_buff* request, struct genl_info* info);
int netlink_insert_routing_table_entry_handler(struct sk_buff* request, struct genl_info* info);
int netlink_insert_dest_routing_table_entry_handler(struct sk_buff* request, struct genl_info* info);
int netlink_insert_interface_table_entry_handler(struct sk_buff* request, struct genl_info* info);
int netlink_set_lir_single_time_encoding_count_handler(struct sk_buff* request, struct genl_info* info);
int netlink_set_sec_path_mab_route(struct sk_buff* request, struct genl_info* info);
int netlink_set_sec_path_mab_route_for_fixed_batch(struct sk_buff *request, struct genl_info *info);
int netlink_set_sec_path_mab_route_for_dynamic_batch(struct sk_buff *request, struct genl_info *info);
int netlink_reset_sec_path_mab_route(struct sk_buff* request, struct genl_info* info);
int netlink_reset_sec_path_mab_route_for_fixed_batch(struct sk_buff *request, struct genl_info *info);
int netlink_reset_sec_path_mab_route_for_dynamic_batch(struct sk_buff *request, struct genl_info *info);
int netlink_set_router_type(struct sk_buff* request, struct genl_info* info);
int netlink_set_sec_path_mab_type(struct sk_buff* request, struct genl_info* info);
int netlink_set_router_malicious_parameters(struct sk_buff* request, struct genl_info* info);
int netlink_retrieve_kernel_information(struct sk_buff* request, struct genl_info* info);
int netlink_retrieve_kernel_information_for_fixed_batch(struct sk_buff* request, struct genl_info* info);
int netlink_retrieve_kernel_information_for_dynamic_batch(struct sk_buff* request, struct genl_info* info);
int netlink_set_scheduled_malicious_params(struct sk_buff* request, struct genl_info* info);
int netlink_set_min_ack_for_rtt_estimation(struct sk_buff *request, struct genl_info *info);
int netlink_set_best_path_id_for_source(struct sk_buff* request, struct genl_info* info);
int print_routing_table_entries(struct sk_buff* request, struct genl_info* info);
#endif //LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
