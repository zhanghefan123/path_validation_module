#include "structure/routing/user_space_info.h"

/**
 * 进行目的地址信息的初始化
 * @param number_of_destinations 目的地的数量
 * @return
 */
struct UserSpaceInfo* initialize_user_space_info(int path_validation_protocol, int number_of_destinations){
    struct UserSpaceInfo* destination_info = (struct UserSpaceInfo*)kmalloc(sizeof(struct UserSpaceInfo), GFP_KERNEL);
    destination_info->path_validation_protocol = path_validation_protocol;
    destination_info->number_of_destinations = number_of_destinations;
    destination_info->destinations = (unsigned char*)kmalloc(number_of_destinations, GFP_KERNEL);
    return destination_info;
}

/**
 * 进行目的地址的释放
 * @param destination_info
 */
void free_user_space_info(struct UserSpaceInfo* destination_info){
    if (NULL != destination_info) {
        if (NULL != destination_info->destinations){
            kfree(destination_info->destinations);
            destination_info->destinations = NULL;
        }
        kfree(destination_info);
        destination_info = NULL;
    }
}
