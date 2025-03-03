#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"

/**
 * 进行 cork 的 release
 * @param cork
 */
static void ip_cork_release(struct inet_cork *cork) {
    cork->flags &= ~IPCORK_OPT;
    kfree(cork->opt);
    cork->opt = NULL;
}

void __ip_flush_pending_frames(struct sock *sk,
                               struct sk_buff_head *queue,
                               struct inet_cork *cork) {
    struct sk_buff *skb;

    while ((skb = __skb_dequeue_tail(queue)) != NULL)
        kfree_skb(skb);

    ip_cork_release(cork);
}