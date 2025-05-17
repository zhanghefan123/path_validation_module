//
// Created by zhf on 24-10-10.
//

#ifndef ZEUSNET_KERNEL_CHECK_SRV6_H
#define ZEUSNET_KERNEL_CHECK_SRV6_H
#include <net/ip.h>
#define HOP_EQUALS_ONE 1
#define HOP_NOT_EQUALS_ONE 2
#define NOT_SRV6_PACKETS 3
int check_if_srv6_and_other(struct sk_buff* skb);
#endif //ZEUSNET_KERNEL_CHECK_SRV6_H
