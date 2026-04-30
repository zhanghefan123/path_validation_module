#include "structure/header/multipath_selir_header.h"

unsigned char* calculate_multipath_selir_hash(struct shash_desc* hash_api, struct MultipathSELiRHeader* multipath_selir_header){
    // check 不作为静态字段来进行哈希 current_path_index 也不是
    int not_calculated_part = sizeof(__sum16) + sizeof(u16);
    // 计算哈希并返回
    return calculate_hash(hash_api,
                          (unsigned char*)(multipath_selir_header),
                          sizeof(struct MultipathSELiRHeader) - not_calculated_part);
}