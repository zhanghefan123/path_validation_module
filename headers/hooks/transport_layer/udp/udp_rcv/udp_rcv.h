//
// Created by zhf on 2024/12/5.
//

#ifndef LOADABLE_KERNEL_MODULE_UDP_RCV_H
#define LOADABLE_KERNEL_MODULE_UDP_RCV_H
#include <net/ip.h>
int pv_udp_rcv(struct sk_buff* skb, __be32 receive_addr);
int pv_udp_rcv_core(struct sk_buff *skb, struct udp_table *udptable, int proto, __be32 recv_addr);
bool resolve_udp_rcv_inner_functions_address(void);
#endif //LOADABLE_KERNEL_MODULE_UDP_RCV_H
