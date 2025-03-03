//
// Created by zhf on 2024/12/5.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_LOCAL_DELIVER_H
#define LOADABLE_KERNEL_MODULE_IP_LOCAL_DELIVER_H
#include <net/ip.h>
int pv_local_deliver(struct sk_buff* skb, int protocol, __be32 receive_interface_addr);
void pv_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol, __be32 receive_interface_addr);
#endif //LOADABLE_KERNEL_MODULE_IP_LOCAL_DELIVER_H
