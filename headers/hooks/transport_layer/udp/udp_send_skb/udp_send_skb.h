//
// Created by 张贺凡 on 2024/11/27.
//

#ifndef LOADABLE_KERNEL_MODULE_UDP_SEND_SKB_H
#define LOADABLE_KERNEL_MODULE_UDP_SEND_SKB_H

#include <net/ip.h>
#include <net/udp.h>
#include "structure/routing/routing_calc_res.h"

int self_defined_udp_send_skb(struct sk_buff *skb,
                              struct flowi4 *fl4,
                              struct inet_cork *cork,
                              struct RoutingCalcRes *rcr,
                              int validation_protocol);

#endif //LOADABLE_KERNEL_MODULE_UDP_SEND_SKB_H
