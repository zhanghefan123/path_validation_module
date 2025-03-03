#include <net/udp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include "tools/tools.h"
#include "hooks/transport_layer/udp/udp_rcv/udp_rcv.h"
#include "structure/header/tools.h"


char* udp_unicast_rcv_skb_str = "udp_unicast_rcv_skb";
asmlinkage int (*orig_udp_unicast_rcv_skb)(struct sock *sk, struct sk_buff *skb,struct udphdr *uh);
DEFINE_STATIC_KEY_FALSE(udp_encap_needed_key);

bool resolve_udp_rcv_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve udp_rcv inner functions address");
    bool resolve_result;
    void *functions[1];
    char* function_names[1] = {
        udp_unicast_rcv_skb_str,
    };
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    // 将函数地址提取
    orig_udp_unicast_rcv_skb = functions[0];
    LOG_WITH_EDGE("end to resolve udp_rcv inner functions address");
    return resolve_result;
}

// 计算伪首部的
static __wsum pv_compute_pseudo(struct sk_buff *skb, int proto)
{
    __u16 source = get_source_from_skb(skb);
    return csum_tcpudp_nofold(source, source,
                              skb->len, proto, 0);
}

static inline struct sock *copy__udp4_lib_lookup_skb(struct sk_buff *skb,
                                                     __be16 sport, __be16 dport,
                                                     struct udp_table *udptable, __be32 recv_addr)
{
    __u16 source = get_source_from_skb(skb);

    return __udp4_lib_lookup(dev_net(skb->dev), source, sport,
                             recv_addr, dport, inet_iif(skb),
                             inet_sdif(skb), udptable, skb); // 这个是暴露的 EXPOSED 的函数
}


static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
                                 int proto)
{
    int err;

    UDP_SKB_CB(skb)->partial_cov = 0;
    UDP_SKB_CB(skb)->cscov = skb->len;

    /* Note, we are only interested in != 0 or == 0, thus the
     * force to int.
     */
    err = (__force int)skb_checksum_init_zero_check(skb, proto, uh->check,
                                                    pv_compute_pseudo);
    if (err)
        return err;

    if (skb->ip_summed == CHECKSUM_COMPLETE && !skb->csum_valid) {
        /* If SW calculated the value, we know it's bad */
        if (skb->csum_complete_sw)
            return 1;

        /* HW says the value is bad. Let's validate that.
         * skb->csum is no longer the full packet checksum,
         * so don't treat it as such.
         */
        skb_checksum_complete_unset(skb);
    }

    return 0;
}

int pv_udp_rcv(struct sk_buff* skb, __be32 receive_addr){
    return pv_udp_rcv_core(skb, &udp_table, IPPROTO_UDP, receive_addr);
}

int pv_udp_rcv_core(struct sk_buff *skb, struct udp_table *udptable, int proto, __be32 receive_addr){
    struct sock *sk;
    struct udphdr *uh;
    unsigned short ulen;
    __be32 saddr, daddr;
    struct net *net = dev_net(skb->dev);
    bool refcounted;
    int drop_reason;
    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
    // 实验所需, 暂不打印
    // LOG_WITH_PREFIX("pv_udp_rcv_core");

    /*
     *  Validate the packet.
     */
    if (!pskb_may_pull(skb, sizeof(struct udphdr)))
        goto drop;		/* No space for header. */

    uh   = udp_hdr(skb);
    ulen = ntohs(uh->len);
    saddr = get_source_from_skb(skb);
    daddr = receive_addr;

    if (ulen > skb->len)
        goto short_packet;

    if (proto == IPPROTO_UDP) {
        /* UDP validates ulen. */
        if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
            goto short_packet;
        uh = udp_hdr(skb);
    }

    if (udp4_csum_init(skb, uh, proto)){
        LOG_WITH_PREFIX("udp4_csum_init error");
        goto csum_error;
    }


    sk = skb_steal_sock(skb, &refcounted);
    if (sk) {
        struct dst_entry *dst = skb_dst(skb);
        int ret;

        if (unlikely(rcu_dereference(sk->sk_rx_dst) != dst))
            udp_sk_rx_dst_set(sk, dst);

        ret = orig_udp_unicast_rcv_skb(sk, skb, uh);
        if (refcounted)
            sock_put(sk);
        return ret;
    }

    sk = copy__udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable, receive_addr);
    if (sk)
        return orig_udp_unicast_rcv_skb(sk, skb, uh);

    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
        goto drop;
    nf_reset_ct(skb);

    /* No socket. Drop packet silently, if checksum is wrong */
    if (udp_lib_checksum_complete(skb)){
        LOG_WITH_PREFIX("udp_lib_checksum_complete error");
        goto csum_error;
    }


    drop_reason = SKB_DROP_REASON_NO_SOCKET;
    __UDP_INC_STATS(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
    icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

    /*
     * Hmm.  We got an UDP packet to a port to which we
     * don't wanna listen.  Ignore it.
     */
    kfree_skb_reason(skb, drop_reason);
    return 0;

    short_packet:
    drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
    net_dbg_ratelimited("UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
                        proto == IPPROTO_UDPLITE ? "Lite" : "",
                        &saddr, ntohs(uh->source),
                        ulen, skb->len,
                        &daddr, ntohs(uh->dest));
    goto drop;

    csum_error:
    /*
     * RFC1122: OK.  Discards the bad packet silently (as far as
     * the network is concerned, anyway) as per 4.1.3.4 (MUST).
     */
    drop_reason = SKB_DROP_REASON_UDP_CSUM;
    net_dbg_ratelimited("UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
                        proto == IPPROTO_UDPLITE ? "Lite" : "",
                        &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
                        ulen);
    __UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
    drop:
    __UDP_INC_STATS(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
    kfree_skb_reason(skb, drop_reason);
    return 0;
}