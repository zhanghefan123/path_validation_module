//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
#define LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
#include <net/ip.h>
struct UserSpaceInfo {
    int path_validation_protocol; // 选择的路径验证协议
    int number_of_destinations;  // 目的地的数量
    unsigned char* destinations; // 目的地
};
struct UserSpaceInfo* initialize_user_space_info(int path_validation_protocol, int number_of_destinations);
void free_user_space_info(struct UserSpaceInfo* destination_info);
#endif //LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
