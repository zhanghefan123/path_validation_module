//
// Created by zhf on 24-10-6.
//
#ifndef ZEUSNET_KERNEL_HOOK_IPV6_RCV_H
#define ZEUSNET_KERNEL_HOOK_IPV6_RCV_H

#include "api/ftrace_hook_api.h"

int self_defined_ipv6_rcv(struct sk_buff *skb,
                          struct net_device *dev,
                          struct packet_type *pt,
                          struct net_device *orig_dev);

void add_ipv6_rcv_to_hook(void);

bool resolve_ipv6_rcv_inner_functions_address(void);

extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;

#endif