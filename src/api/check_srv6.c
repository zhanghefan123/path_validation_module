#include "api/check_srv6.h"
#include "tools/tools.h"
#include <net/seg6.h>

/**
 * 检测是否数据包结构 [ipv6->srv6->ipv6->tcp/udp] -> 并且是第一跳
 * @param skb 数据包
 * @return true 代表是
 */
bool check_if_srv6_and_tcp(struct sk_buff* skb){
    // 获取总的跳数
    int total_hops;
    // 已经经过的跳数
    int hop_traversed;
    // 获取 ipv6 报文头的大小
    int ipv6_header_size = sizeof(struct ipv6hdr);
    // 进行 ipv6 标准报头的提取
    struct ipv6hdr* ipv6_header = ipv6_hdr(skb);
    // 提取 next header 字段
    if(ipv6_header->nexthdr == NEXTHDR_ROUTING) {
        // 将指针指向 ipv6 header 内部所包含的 srv6 header
        struct ipv6_sr_hdr* srv6_header = (struct ipv6_sr_hdr*)((unsigned char*)ipv6_header + ipv6_header_size);

        // 获取总的跳数
        total_hops = srv6_header->first_segment + 1;

        // 判断已经经过的跳数
        hop_traversed = total_hops - srv6_header->segments_left;

        if (srv6_header->nexthdr == NEXTHDR_IPV6){
            // 将指针指向 srv6 header 内部所包含的 ipv6 header
            struct ipv6hdr* ipv6_header_inside = (struct ipv6hdr*)((unsigned char*)(srv6_header) + ipv6_optlen(srv6_header));
            // 如果最内部包含的 ipv6 header 的 nexthdr 字段为 TCP, 那么说明是我们发送的数据包
            if(((ipv6_header_inside->nexthdr == IPPROTO_TCP) || (ipv6_header_inside->nexthdr == IPPROTO_UDP)) && (hop_traversed == 1)){
                return true;
            }
        }
    }
    return false;
}