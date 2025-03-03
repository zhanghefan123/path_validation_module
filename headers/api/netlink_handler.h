//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
#define LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
#include <net/sock.h>
#include <net/genetlink.h>
char* recv_message(struct genl_info* info);
int send_reply(char* response_buffer, struct genl_info* info);
int netlink_echo_handler(struct sk_buff* request, struct genl_info* info);
int netlink_set_node_id_handler(struct sk_buff* request, struct genl_info* info);
int netlink_init_routing_and_forwarding_table_handler(struct sk_buff* request, struct genl_info* info);
int netlink_init_selir(struct sk_buff* request, struct genl_info* info);
int netlink_init_bloom_filter_handler(struct sk_buff* request, struct genl_info* info);
int netlink_insert_routing_table_entry_handler(struct sk_buff* request, struct genl_info* info);
int netlink_insert_interface_table_entry_handler(struct sk_buff* request, struct genl_info* info);
#endif //LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
