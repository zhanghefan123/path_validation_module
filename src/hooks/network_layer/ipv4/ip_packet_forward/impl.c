#include <net/ip.h>
#include <linux/netdevice.h>
#include "tools/tools.h"
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

/**
 * 进行数据包的转发
 * @param skb skb
 * @param output_interface 出接口
 * @param current_ns 当前网络命名空间
 * @return
 */
int pv_packet_forward(struct sk_buff* skb, struct InterfaceTableEntry* ite, struct net* current_ns){
    if (NULL != ite){
        // 最大数据传输单元
        u32 mtu = READ_ONCE(ite->interface->mtu);
        // socket
        struct sock* sk = NULL;
        // reason 原因
        SKB_DR(reason);
        // 进行 L2 层头部空间的预留
        skb_cow(skb, LL_RESERVED_SPACE(ite->interface));
        // 如果 ip 层校验和策略，则修改为 None
        skb_forward_csum(skb);
        // 将 skb 修改为出口网络设备
        skb->dev = ite->interface;
        // 设置链路层协议
        skb->protocol = htons(ETH_P_IP);
        // 当超过 mtu 限制, 需要进行分片
        return pv_finish_output2(current_ns, sk, skb, ite);
    } else {
        LOG_WITH_PREFIX("output interface == NULL");
        return 0;
    }
}