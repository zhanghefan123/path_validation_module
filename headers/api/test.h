//
// Created by zhf on 2024/11/21.
//

#ifndef PVM_TEST_H
#define PVM_TEST_H
#include <net/ip.h>
// 定义的网络类型
#define NORMAL_SOCKET_TYPE 1
#define LINK_IDENTIFIED_SOCKET_TYPE 2

// 已有的协议类型
#define IP_VERSION_NUMBER 4
#define IP6_VERSION_NUMBER 6

// 自定义的协议类型
#define LIR_VERSION_NUMBER 1
#define ICING_VERSION_NUMBER 2
#define OPT_VERSION_NUMBER 3
// 编号4 留给 ipv4
#define SELIR_VERSION_NUMBER 5
// 编号6 留给 ipv6
#define FAST_SELIR_VERSION_NUMBER 7
#define MULTICAST_SELIR_VERSION_NUMBER 8
#define SESSION_SETUP_VERSION_NUMBER 9
#define MULTICAST_SESSION_SETUP_VERSION_NUMBER 10
#define EPIC_SESSION_VERSION_NUMBER 11
#define EPIC_VERSION_NUMBER 12
#define ATLAS_VERSION_NUMBER 13
#define MULTIPATH_SELIR_VERSION_NUMBER (12)
#define MULTICAST_OPT_VERSION_NUMBER (13)
#define SEC_PATH_MAB_VERSION_NUMBER 14
#define SEC_PATH_MAB_ACK_VERSION_NUMBER 15
// 注意这里不能超过 15 后面需要进行更改 (Multipath selir version number 和 multicast opt version number 已经进行了更改)

void test_apis(void);
int resolve_socket_type(struct sock* sk);
#endif //PVM_TEST_H
