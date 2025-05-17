#include "hooks/network_layer/ipv6/ipv6_rcv_finish/ipv6_rcv_finish.h"
#include "hooks/network_layer/ipv6/ip6_rcv_finish_core/ip6_rcv_finish_core.h"
#include "tools/tools.h"
#include "api/check_srv6.h"
#include <net/ip.h>

/**
 * 自定义的 ip6_rcv_finish 函数
 * @param net 网络命名空间
 * @param sk sock
 * @param skb 数据包
 * @return
 */
int self_defined_ip6_rcv_finish(struct net *net,
                                struct sock *sk,
                                struct sk_buff *skb,
                                int is_srv6_and_tcp_packet,
                                u64 start_time) {
    /* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
    skb = l3mdev_ip6_rcv(skb); // 这是在 header 之中内联的函数
    if (!skb)
        return NET_RX_SUCCESS;
    self_defined_ip6_rcv_finish_core(net, sk, skb);


    // 将 dst_input 的调用进行提前
    int result = dst_input(skb);

    // 打印函数的名称
//    if (is_srv6_and_tcp_packet == HOP_EQUALS_ONE) {
//        u64 time_elapsed = ktime_get_real_ns() - start_time;
//       //  printk(KERN_EMERG "srv6 forwarding takes %llu ns", time_elapsed);
//    }

    return result;
}

