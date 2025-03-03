//
// Created by kernel-dbg on 24-2-1.
//
#include <net/sock.h>
#include "tools/tools.h"
#include "api/hook_functions_api.h"
#include "api/ftrace_hook_api.h"
#include "prepare/resolve_function_address.h"
#include "hooks/network_layer/ipv6/ipv6_rcv/ipv6_rcv.h"
#include "hooks/transport_layer/tcp/tcp_v4_rcv/tcp_v4_rcv.h"
#include "hooks/transport_layer/udp/udp_sendmsg/udp_sendmsg.h"
#include "hooks/inet_sendmsg/inet_sendmsg.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"


// 我们添加的 hook 列表, 假设最多10个
struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];

// 我们当前的 hook 的个数
int number_of_hook = 0;

// 进行hook的安装
int install_hook_functions(void){
    add_ipv6_rcv_to_hook(); // 进行 ipv6_rcv hook 的安装
    add_tcp_v4_rcv_to_hook(); // 进行 tcp_v4_rcv hook 的安装
    add_inet_sendmsg_to_hook(); // 进行 inet_sendmsg hook 的安装
    add_ip_rcv_to_hook(); // 进行 ip_rcv hook 的安装
    fh_install_hooks(hooks, number_of_hook);
    LOG_WITH_PREFIX("already install hooks");
    tidy();
    return 0;
}

/**
 * 进行 hook 的卸载
 */
void uninstall_hook_functions(void) {
    fh_remove_hooks(hooks, number_of_hook);
    LOG_WITH_PREFIX("already uninstall hooks\n");
}

/**
 * 进行清理任务
 */
void tidy(void) {
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}

/**
 * 进行钩子函数的绑定
 */
void start_install_hooks(void) {
    install_hook_functions();
}

/**
 * 进行钩子函数的解绑
 */
void exit_uninstall_hooks(void) {
    uninstall_hook_functions();
}
