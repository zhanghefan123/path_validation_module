#include <linux/udp.h>
#include "api/test.h"
#include "structure/header/lir_header.h"
#include "structure/header/icing_header.h"
#include "hooks/transport_layer/udp/udp_send_skb/udp_send_skb.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/header/fast_selir_header.h"
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "structure/header/multicast_session_header.h"

/**
 * 进行 udp 层的定义
 * @param skb 数据包
 * @param fl4 流信息
 * @param cork corking 状态
 * @return
 */
int self_defined_udp_send_skb(struct sk_buff *skb,
                              struct flowi4 *fl4,
                              struct inet_cork *cork,
                              struct RoutingCalcRes *rcr,
                              int validation_protocol) {
    struct sock *sk = skb->sk;
    struct inet_sock *inet = inet_sk(sk);
    struct udphdr *uh;
    int err;
    int is_udplite = IS_UDPLITE(sk);
    int offset = skb_transport_offset(skb);
    int len = skb->len - offset;
    int datalen = len - sizeof(*uh);
    __wsum csum = 0;

    /*
     * Create a UDP header
     */
    int source_identification;
    if (LIR_VERSION_NUMBER == validation_protocol){
        struct LiRHeader *lir_header = lir_hdr(skb);
        source_identification = lir_header->source;
    } else if(ICING_VERSION_NUMBER == validation_protocol){
        struct ICINGHeader* icing_header = icing_hdr(skb);
        source_identification = icing_header->source;
    } else if (OPT_VERSION_NUMBER == validation_protocol) {
        // 因为这里不涉及到选项字段的提取, 所以只需要判断是否是 OPT_VERSION_NUMBER
        struct OptHeader* opt_header = opt_hdr(skb);
        source_identification = opt_header->source;
    } else if (SELIR_VERSION_NUMBER == validation_protocol){
        struct SELiRHeader* selir_header = selir_hdr(skb);
        source_identification = selir_header->source;
    } else if (FAST_SELIR_VERSION_NUMBER == validation_protocol){
        struct FastSELiRHeader* fast_selir_header = fast_selir_hdr(skb);
        source_identification = fast_selir_header->source;
    } else if (MULTICAST_SELIR_VERSION_NUMBER == validation_protocol){
        struct MulticastSessionHeader* multicast_session_header = multicast_session_hdr(skb);
        source_identification = multicast_session_header->source;
    }
    else {
        LOG_WITH_PREFIX("current not supported protocol");
    }

    uh = udp_hdr(skb);
    uh->source = inet->inet_sport;
    uh->dest = fl4->fl4_dport;
    uh->len = htons(len);
    uh->check = 0;

    if (cork->gso_size) {
        const int hlen = skb_network_header_len(skb) +
                         sizeof(struct udphdr);

        if (hlen + cork->gso_size > cork->fragsize) {
            kfree_skb(skb);
            return -EINVAL;
        }
        if (datalen > cork->gso_size * UDP_MAX_SEGMENTS) {
            kfree_skb(skb);
            return -EINVAL;
        }
        if (sk->sk_no_check_tx) {
            kfree_skb(skb);
            return -EINVAL;
        }
        if (skb->ip_summed != CHECKSUM_PARTIAL || is_udplite ||
            dst_xfrm(skb_dst(skb))) {
            kfree_skb(skb);
            return -EIO;
        }

        if (datalen > cork->gso_size) {
            skb_shinfo(skb)->gso_size = cork->gso_size;
            skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
            skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(datalen,
                                                     cork->gso_size);
        }
        goto csum_partial;
    }

    if (sk->sk_no_check_tx) {             /* UDP csum off */

        skb->ip_summed = CHECKSUM_NONE;
        goto send;

    } else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
        csum_partial:

        udp4_hwcsum(skb, source_identification, source_identification);
        goto send;

    } else
        csum = udp_csum(skb);


    /* add protocol-dependent pseudo-header */
    // 添加上伪首部, 并进行校验和的计算
    uh->check = csum_tcpudp_magic(source_identification, source_identification, len, sk->sk_protocol, csum);
    if (uh->check == 0)
        uh->check = CSUM_MANGLED_0;



    // 进行数据的发送
    send:
    // -------------------------------------------------------------
    struct net_device *dev = rcr->ite->interface;
    IP_UPD_PO_STATS(sock_net(sk), IPSTATS_MIB_OUT, skb->len);
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    err = pv_finish_output2(sock_net(sk), sk, skb, rcr->ite);
    // -------------------------------------------------------------
    if (err) {
        if (err == -ENOBUFS && !inet->recverr) {
            UDP_INC_STATS(sock_net(sk),
                          UDP_MIB_SNDBUFERRORS, is_udplite);
            err = 0;
        }
    } else
        UDP_INC_STATS(sock_net(sk),
                      UDP_MIB_OUTDATAGRAMS, is_udplite);
    return err;
}