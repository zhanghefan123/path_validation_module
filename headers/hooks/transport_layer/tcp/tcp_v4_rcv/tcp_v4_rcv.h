//
// Created by 张贺凡 on 2024/11/18.
//

#ifndef LOADABLE_KERNEL_MODULE_TCP_V4_RCV_H
#define LOADABLE_KERNEL_MODULE_TCP_V4_RCV_H
#include "api/ftrace_hook_api.h"
#include <linux/types.h>

int self_defined_tcp_v4_rcv(struct sk_buff *skb);

void add_tcp_v4_rcv_to_hook(void);

bool resolve_tcp_v4_rcv_inner_functions_address(void);

extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;

#endif //LOADABLE_KERNEL_MODULE_TCP_V4_RCV_H
