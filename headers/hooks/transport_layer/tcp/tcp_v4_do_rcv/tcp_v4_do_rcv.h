//
// Created by 张贺凡 on 2024/11/18.
//

#ifndef LOADABLE_KERNEL_MODULE_TCP_V4_DO_RCV_H
#define LOADABLE_KERNEL_MODULE_TCP_V4_DO_RCV_H
#include <net/ip.h>

bool resolve_tcp_v4_do_rcv_inner_functions_address(void);

int self_defined_tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb, const struct tcphdr* th);

#endif //LOADABLE_KERNEL_MODULE_TCP_V4_DO_RCV_H
