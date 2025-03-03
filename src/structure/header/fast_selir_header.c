#include "structure/header/fast_selir_header.h"

unsigned char* calculate_fast_selir_hash(struct shash_desc* hash_api, struct FastSELiRHeader* fast_selir_header){
    // check 不作为静态字段来进行哈希
    int not_calculated_part = sizeof(__sum16);
    // 计算哈希并返回
    return calculate_hash(hash_api,
                          (unsigned char*)(fast_selir_header),
                          sizeof(struct FastSELiRHeader) - not_calculated_part);
}