//
// Created by zhf on 24-10-10.
//

#ifndef ZEUSNET_KERNEL_IP6_RCV_FINISH_CORE_H
#define ZEUSNET_KERNEL_IP6_RCV_FINISH_CORE_H
#include <net/ip.h>
void self_defined_ip6_rcv_finish_core(struct net* net, struct sock* sk, struct sk_buff* skb);
bool resolve_ip6_rcv_finish_core_inner_functions_address(void);
#endif //ZEUSNET_KERNEL_IP6_RCV_FINISH_CORE_H
