//
// Created by zhf on 24-10-10.
//

#ifndef ZEUSNET_KERNEL_IPV6_RCV_FINISH_H
#define ZEUSNET_KERNEL_IPV6_RCV_FINISH_H

#include <net/ip.h>

int self_defined_ip6_rcv_finish(struct net *net,
                                struct sock *sk,
                                struct sk_buff *skb,
                                bool is_srv6_and_tcp_packet,
                                u64 start_time);

#endif //ZEUSNET_KERNEL_IPV6_RCV_FINISH_H
