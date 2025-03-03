#include "tools/tools.h"
#include "api/ftrace_hook_api.h"
#include "hooks/network_layer/ipv6/ip6_rcv_finish_core/ip6_rcv_finish_core.h"

char* tcp_v6_early_demux_str = "tcp_v6_early_demux";
char *udp_v6_early_demux_str = "udp_v6_early_demux";
char *ip6_route_input_str = "ip6_route_input";

asmlinkage void (*original_tcp_v6_early_demux)(struct sk_buff *skb);
asmlinkage void (*original_udp_v6_early_demux)(struct sk_buff *skb);
asmlinkage void (*original_ip6_route_input)(struct sk_buff *skb);

static inline bool skb_valid_dst(const struct sk_buff *skb) {
    struct dst_entry *dst = skb_dst(skb);
    return dst && !(dst->flags & DST_METADATA);
}

bool resolve_ip6_rcv_finish_core_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve ip6_rcv_finish_core inner functions address");
    // 解析结果
    bool resolve_result;
    // 所有的待初始化的函数指针构成的数组
    void* functions[3];
    char* function_names[3] = {
            tcp_v6_early_demux_str,
            udp_v6_early_demux_str,
            ip6_route_input_str
    };
    resolve_result = resolve_functions_addresses(functions, function_names, 3);
    original_tcp_v6_early_demux = functions[0];
    original_udp_v6_early_demux = functions[1];
    original_ip6_route_input = functions[2];
    LOG_WITH_EDGE("end to resolve ip6_rcv_finish_core inner functions address");
    return resolve_result;
}

void self_defined_ip6_rcv_finish_core(struct net *net, struct sock *sk,
                                struct sk_buff *skb)
{
    if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) &&
        !skb_dst(skb) && !skb->sk) {
        switch (ipv6_hdr(skb)->nexthdr) {
            case IPPROTO_TCP:
                if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux))
                    original_tcp_v6_early_demux(skb);
                break;
            case IPPROTO_UDP:
                if (READ_ONCE(net->ipv4.sysctl_udp_early_demux))
                    original_udp_v6_early_demux(skb);
                break;
        }
    }

    if (!skb_valid_dst(skb))
        original_ip6_route_input(skb);
}
