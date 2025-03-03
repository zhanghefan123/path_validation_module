#include "hooks/network_layer/ipv4/ip_send_skb/ip_send_skb.h"
#include "hooks/network_layer/ipv4/ip_local_out/ip_local_out.h"

int self_defined_path_validation_send_skb(struct net *net, struct sk_buff *skb, struct RoutingCalcRes* rcr)
{
    int err;
    err = pv_local_out(net, skb->sk, skb, rcr);
    if (err) {
        if (err > 0)
            err = net_xmit_errno(err);
        if (err)
            IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
    }
    return err;
}