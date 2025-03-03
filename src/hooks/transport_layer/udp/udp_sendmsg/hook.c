#include "api/test.h"
#include "tools/tools.h"
#include "hooks/transport_layer/udp/udp_sendmsg/udp_sendmsg.h"


// 原来的函数地址
char* udp_sendmsg_str = "udp_sendmsg";
asmlinkage int (*orig_udp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t len); // 原来的 udp_sendmsg


bool resolve_udp_sendmsg_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve udp_sendmsg inner functions address");
    // 结果
    bool resolve_result;
    // 所有的待初始化的函数指针构成的数组
    void* functions[1];
    // 所有的函数名
    char* function_names[1] = {
            udp_sendmsg_str
    };
    // 解析函数地址
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    // 将函数地址提取
    orig_udp_sendmsg = functions[0];
    LOG_WITH_EDGE("end to resolve udp_sendmsg inner functions address");
    return resolve_result;
}


///**
// * callback function
// * @param sk
// * @param msg
// * @param len
// * @return
// */
//asmlinkage int hook_udp_sendmsg(struct sock* sk, struct msghdr* msg, size_t len){
//    int network_type = resolve_socket_type(sk);
//    if (NORMAL_SOCKET_TYPE == network_type) {
//        return orig_udp_sendmsg(sk, msg, len);
//    } else if (LINK_IDENTIFIED_SOCKET_TYPE == network_type){
//        return self_defined_udp_sendmsg(sk,msg,len);
//    } else {
//        LOG_WITH_PREFIX("unsupported network type");
//        return -EINVAL;
//    }
//}