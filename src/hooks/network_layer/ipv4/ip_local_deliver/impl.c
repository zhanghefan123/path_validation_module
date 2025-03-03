#include <net/protocol.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include "structure/header/lir_header.h"
#include "hooks/transport_layer/udp/udp_rcv/udp_rcv.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"

extern asmlinkage int (*orig_tcp_v4_rcv)(struct sk_buff* skb);

/**
 * 进行本地的交付
 * @param skb 数据包
 * @param protocol 传输层协议
 * @param receive_interface_addr 接受的 ip 地址
 * @return
 */
int pv_local_deliver(struct sk_buff* skb, int protocol, __be32 receive_interface_addr){
    struct net* net = dev_net(skb->dev);
    skb_clear_delivery_time(skb);
    __skb_pull(skb, skb_network_header_len(skb));
    rcu_read_lock();
    // ---------------------------------------------------------------
    pv_protocol_deliver_rcu(net, skb, protocol, receive_interface_addr);
    // ---------------------------------------------------------------
    rcu_read_unlock();
    return 0;
}

void pv_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol, __be32 receive_addr){
    const struct net_protocol *ipprot;
    int raw, ret;

    resubmit:
    ipprot = rcu_dereference(inet_protos[protocol]);
    if (ipprot) {
        if (!ipprot->no_policy) {
            if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
                kfree_skb_reason(skb,
                                 SKB_DROP_REASON_XFRM_POLICY);
                return;
            }
            nf_reset_ct(skb);
        }
        if(ipprot->handler == orig_tcp_v4_rcv){
            // original code
            orig_tcp_v4_rcv(skb);
        } else {
            ret = pv_udp_rcv(skb, receive_addr);
        }
        if (ret < 0) {
            protocol = -ret;
            goto resubmit;
        }
        __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
    } else {
        if (!raw) {
            if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
                __IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
                icmp_send(skb, ICMP_DEST_UNREACH,
                          ICMP_PROT_UNREACH, 0);
            }
            kfree_skb_reason(skb, SKB_DROP_REASON_IP_NOPROTO);
        } else {
            __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
            consume_skb(skb);
        }
    }
}