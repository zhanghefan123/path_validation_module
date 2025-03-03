#include <linux/netfilter.h>
#include "tools/tools.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_local_out/ip_local_out.h"
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/header/icing_header.h"

int pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct RoutingCalcRes* rcr){
    return __pv_local_out(net, sk, skb, rcr);
}

int __pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct RoutingCalcRes* rcr){
    return pv_output(net, sk, skb, rcr->ite);
}