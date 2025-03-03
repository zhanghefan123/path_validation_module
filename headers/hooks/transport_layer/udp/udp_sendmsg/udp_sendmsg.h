//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_UDP_SEND_MSG_H
#define LOADABLE_KERNEL_MODULE_UDP_SEND_MSG_H

#include "api/ftrace_hook_api.h"

bool resolve_udp_sendmsg_inner_functions(void);

int self_defined_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);

bool resolve_udp_sendmsg_inner_functions_address(void);

extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;

#endif //LOADABLE_KERNEL_MODULE_UDP_SEND_MSG_H
