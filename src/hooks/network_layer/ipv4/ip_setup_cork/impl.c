#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"


/**
 * corking 机制是一种延迟发送的技术，允许将多个数据包聚合成一个大的数据包以提升效率
 * @param sk 套接字
 * @param cork 用于保存和初始化 corking 状态。改结构体主要缓存数据包的一些信息, 直到数据包能够合并或者准备好发送
 * @param ipc 包含 ip 层的配置信息 (路由, TTL, TOS, 标记，优先级等)。
 * @param rtp 指向路由条目的指针
 * @return
 */
int self_defined_ip_setup_cork(struct sock *sk, struct inet_cork *cork, struct ipcm_cookie *ipc, struct RoutingCalcRes* rcr) {
    cork->fragsize = rcr->ite->interface->mtu;
    if (!inetdev_valid_mtu(cork->fragsize))
        return -ENETUNREACH;
    cork->gso_size = ipc->gso_size;
    cork->length = 0;
    cork->ttl = ipc->ttl;
    cork->tos = ipc->tos;
    cork->mark = ipc->sockc.mark;
    cork->priority = ipc->priority;
    cork->transmit_time = ipc->sockc.transmit_time;
    cork->tx_flags = 0;
    sock_tx_timestamp(sk, ipc->sockc.tsflags, &cork->tx_flags);
    return 0;
}