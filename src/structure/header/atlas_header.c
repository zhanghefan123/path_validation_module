#include "structure/header/atlas_header.h"
#include "tools/tools.h"


unsigned char *calculate_atlas_hash(struct shash_desc *hash_api, struct AtlasHeader *atlas_header) {
    // check 和 current_path_index 不作为静态字段来进行哈希
    int not_calculated_part = sizeof(__sum16) + sizeof(__u16);
    // 计算哈希并返回
    return calculate_hash(hash_api,
                          (unsigned char *) (atlas_header),
                          sizeof(struct AtlasHeader) - not_calculated_part);
}

