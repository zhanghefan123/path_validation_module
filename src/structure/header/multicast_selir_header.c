#include "structure/header/multicast_selir_header.h"

unsigned char* calculate_multicast_selir_hash(struct shash_desc* hash_api, struct MulticastSelirHeader* multicast_selir_header){
    // check 不作为静态字段来进行哈希
    int not_calculated_part = sizeof(__sum16);
    // 计算哈希并返回
    return calculate_hash(hash_api,
                          (unsigned char*)(multicast_selir_header),
                          sizeof(struct MulticastSelirHeader) - not_calculated_part);
}