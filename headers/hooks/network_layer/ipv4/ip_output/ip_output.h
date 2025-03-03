//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_OUTPUT_H
#define LOADABLE_KERNEL_MODULE_IP_OUTPUT_H
#include <net/ip.h>
#include "structure/interface/interface_table.h"
int pv_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite);
int pv_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite);
int pv__ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite);
int pv_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite);
#endif //LOADABLE_KERNEL_MODULE_IP_OUTPUT_H
