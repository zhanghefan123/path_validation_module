//
// Created by zhf on 2024/11/29.
//

#ifndef LOADABLE_KERNEL_MODULE_INET_SENDMSG_H
#define LOADABLE_KERNEL_MODULE_INET_SENDMSG_H
#include "api/ftrace_hook_api.h"

void add_inet_sendmsg_to_hook(void);

int hook_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);

bool resolve_inet_sendmsg_inner_functions_address(void);

int self_defined_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);

extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif //LOADABLE_KERNEL_MODULE_INET_SENDMSG_H
