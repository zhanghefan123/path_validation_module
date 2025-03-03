//
// Created by zhf on 24-10-10.
//

#ifndef ZEUSNET_KERNEL_CHECK_SRV6_H
#define ZEUSNET_KERNEL_CHECK_SRV6_H
#include <net/ip.h>
bool check_if_srv6_and_tcp(struct sk_buff* skb);
#endif //ZEUSNET_KERNEL_CHECK_SRV6_H
