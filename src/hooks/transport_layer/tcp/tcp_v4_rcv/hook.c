#include <net/ip.h>
#include "hooks/transport_layer/tcp/tcp_v4_rcv/tcp_v4_rcv.h"

asmlinkage int (*orig_tcp_v4_rcv)(struct sk_buff* skb);

asmlinkage int hook_tcp_v4_rcv(struct sk_buff*skb){
    return self_defined_tcp_v4_rcv(skb);
}

void add_tcp_v4_rcv_to_hook(void){
    hooks[number_of_hook].name = "tcp_v4_rcv";
    hooks[number_of_hook].function = hook_tcp_v4_rcv,
    hooks[number_of_hook].original = &orig_tcp_v4_rcv;
    number_of_hook += 1;
}