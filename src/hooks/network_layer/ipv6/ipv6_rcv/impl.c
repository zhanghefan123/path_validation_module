#include <linux/netfilter.h>
#include "tools/tools.h"
#include "hooks/network_layer/ipv6/ipv6_rcv/ipv6_rcv.h"
#include "hooks/network_layer/ipv6/ipv6_rcv_finish/ipv6_rcv_finish.h"
#include "api/check_srv6.h"

char* ip6_rcv_core_str = "ip6_rcv_core";

asmlinkage struct sk_buff *(*original_ip6_rcv_core)(struct sk_buff *skb, struct net_device *dev, struct net *net);

/**
 * 进行 ipv6_rcv 内部函数的解析
 * @return
 */
bool resolve_ipv6_rcv_inner_functions_address(void) {
    LOG_WITH_EDGE("start to resolve ipv6_rcv inner functions address");
    // 结果
    bool resolve_result;
    // 所有的待初始化的函数指针构成的数组
    void* functions[1];
    // 所有的函数名
    char* function_names[1] = {
            ip6_rcv_core_str
    };
    // 解析函数地址
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    // 将函数地址提取
    original_ip6_rcv_core = functions[0];
    LOG_WITH_EDGE("end to resolve ipv6_rcv inner functions address");
    return resolve_result;
}

/**
 *
 * 自定义 ipv6_rcv
 * @param skb 数据包
 * @param dev 设备
 * @param pt 数据包类型
 * @param orig_dev 入设备
 * @return
 */
int self_defined_ipv6_rcv(struct sk_buff *skb,
                          struct net_device *dev,
                          struct packet_type *pt,
                          struct net_device *orig_dev){
    // 记录开始的时间
    u64 start_time;

    // 检测是否是 srv6 并且上层承载的是 TCP 数据包
    bool is_srv6_and_tcp_packet = check_if_srv6_and_tcp(skb);

    // 获取开始时间
    start_time = ktime_get_real_ns();

    struct net *net = dev_net(skb->dev);

    skb = original_ip6_rcv_core(skb, dev, net);
    if (skb == NULL) {
        return NET_RX_DROP;
    }


    int result = self_defined_ip6_rcv_finish(net, NULL, skb, is_srv6_and_tcp_packet, start_time);

    return result;
}