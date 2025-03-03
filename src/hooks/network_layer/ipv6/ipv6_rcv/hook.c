//
// Created by zhf on 24-10-6.
//
#include "tools/tools.h"
#include "hooks/network_layer/ipv6/ipv6_rcv/ipv6_rcv.h"

asmlinkage int (*orig_ipv6_rcv)(struct sk_buff *skb,struct net_device *dev, struct packet_type *pt,struct net_device *orig_dev);

asmlinkage int hook_ipv6_rcv(struct sk_buff *skb,
                             struct net_device *dev,
                             struct packet_type *pt,
                             struct net_device *orig_dev) {
    return self_defined_ipv6_rcv(skb, dev, pt, orig_dev);
}


void add_ipv6_rcv_to_hook(void){
    LOG_WITH_PREFIX("add ipv6_rcv to hook");
    hooks[number_of_hook].name = "ipv6_rcv";
    hooks[number_of_hook].function = hook_ipv6_rcv;
    hooks[number_of_hook].original = &orig_ipv6_rcv;
    number_of_hook += 1;
}