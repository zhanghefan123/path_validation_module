#include <linux/bpf-cgroup.h>
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "tools/tools.h"

int pv_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite){
    struct net_device *dev = ite->interface;

    IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    return pv_finish_output(net, sk, skb, ite);
}

int pv_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite) {
    int ret;

    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
        case NET_XMIT_SUCCESS:
            return pv__ip_finish_output(net, sk, skb, ite);
        case NET_XMIT_CN:
            return pv__ip_finish_output(net, sk, skb, ite) ?: ret;
        default:
            kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
            return ret;
    }
}

int pv__ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite) {
    return pv_finish_output2(net, sk, skb, ite);
}

static inline int self_defined_neigh_output(struct neighbour *n, struct sk_buff *skb,
                               bool skip_cache)
{
    const struct hh_cache *hh = &n->hh;

    /* n->nud_state and hh->hh_len could be changed under us.
     * neigh_hh_output() is taking care of the race later.
     */
    if (!skip_cache &&
        (READ_ONCE(n->nud_state) & NUD_CONNECTED) &&
        READ_ONCE(hh->hh_len)){
        return neigh_hh_output(hh, skb);
    }
    return n->output(n, skb);
}

// 这个函数为什么耗时这么长 -> 因为这个函数中的函数调用了一个耗时的函数 -> neigh_output -> 但是 ip 为什么不需要这么久 -->
int pv_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb, struct InterfaceTableEntry* ite) {
    struct net_device *dev = ite->interface;
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    struct neighbour *neigh;
    bool is_v6gw = false;

    if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
        skb = skb_expand_head(skb, hh_len);
        if (!skb)
            return -ENOMEM;
    }
    rcu_read_lock_bh();
    neigh = ip_neigh_gw4(dev, ite->peer_ip_address);
    if (!IS_ERR(neigh)) {
        int res;
        sock_confirm_neigh(skb, neigh);
        /* if crossing protocols, can not use the cached header */
        res = self_defined_neigh_output(neigh, skb, is_v6gw);
        rcu_read_unlock_bh();
        return res;
    }
    rcu_read_unlock_bh();

    net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
                        __func__);
    kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
    return -EINVAL;
}
