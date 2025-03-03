#include <net/ip.h>
#include "hooks/inet_sendmsg/inet_sendmsg.h"
#include "tools/tools.h"

asmlinkage int (*orig_inet_sendmsg)(struct socket *sock, struct msghdr *msg, size_t size);

asmlinkage int hook_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size){
    return self_defined_inet_sendmsg(sock, msg, size);
}

void add_inet_sendmsg_to_hook(void){
    hooks[number_of_hook].name = "inet_sendmsg";
    hooks[number_of_hook].function = hook_inet_sendmsg,
    hooks[number_of_hook].original = &orig_inet_sendmsg;
    number_of_hook += 1;
}