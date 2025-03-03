//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_OPTION_RESOLVER_H
#define LOADABLE_KERNEL_MODULE_OPTION_RESOLVER_H
#include "structure/routing/user_space_info.h"
#define PATH_VALIDATION_PROTOCOL_INDEX 2
#define NUMBER_OF_DESTINATIONS_INDEX 3
#define DESTINATIONS_START_INDEX 4
// 这里的起始 index 为 2 的原因是, 第一个字节是 type, 第二个字节是 length
struct UserSpaceInfo* resolve_opt_for_dest_and_proto_info(struct ip_options_rcu* opt);
#endif //LOADABLE_KERNEL_MODULE_OPTION_RESOLVER_H
