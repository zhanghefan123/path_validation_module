#include "structure/header/multicast_opt_header.h"

unsigned char* calculate_multicast_opt_hash(struct shash_desc* hash_api, struct MulticastOptHeader* multicast_opt_header){
    // check 和 current_path_index 无需进行计算
    int not_calculated_part = sizeof(__sum16) + sizeof(__u16);
    return calculate_hash(hash_api,
                          (unsigned char*)(multicast_opt_header),
                          sizeof(struct MulticastOptHeader) - not_calculated_part);
}