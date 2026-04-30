//
// Created by 张贺凡 on 2024/11/27.
//

#ifndef LOADABLE_KERNEL_MODULE_UDP_SEND_SKB_H
#define LOADABLE_KERNEL_MODULE_UDP_SEND_SKB_H

#include <net/ip.h>
#include <net/udp.h>
#include "structure/routing/routing_calc_res.h"
#include "structure/routing/multipath_res.h"

int self_defined_udp_send_skb(struct sk_buff *skb,
                              struct flowi4 *fl4,
                              struct inet_cork *cork,
                              struct RoutingCalcRes *rcr,
                              struct EpicSessionTableEntry* este,
                              struct MultipathRes* mres,
                              struct SecPathMabRoute* sec_path_mab_route,
                              int validation_protocol);

#endif //LOADABLE_KERNEL_MODULE_UDP_SEND_SKB_H
