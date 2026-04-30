#include "structure/header/sec_path_mab_header.h"
#include "tools/tools.h"


unsigned char *calculate_sec_path_mab_hash(struct shash_desc *hash_api, struct SecPathMabHeader *mab_header, struct TimeStamp* timestamp) {
    unsigned char *data[2] = {
            (unsigned char*)(mab_header),
            (unsigned char*)(timestamp)
    };

    int not_calculated_part = sizeof(__sum16) + sizeof(__u16); // current path index and the length of path

    int lengths[2] = {
            sizeof(struct SecPathMabHeader) - not_calculated_part,
            sizeof(struct TimeStamp)
    };

    unsigned char* sec_path_mab_hash = calculate_hash_from_multiple_segments(hash_api, data, lengths, 2);
    return sec_path_mab_hash;
}

int get_sec_path_mab_header_size(int number_of_hop_identifiers, int number_of_hvfs) {
    // 标准首部 + 元数据 + 路径部分 + 验证部分
    int result = sizeof(struct SecPathMabHeader) +
                 sizeof(struct SecPathMabMetadata) +
                 sizeof(struct SecPathMabHopIdentifier) * number_of_hop_identifiers +
                 sizeof(struct MabPvf) + sizeof(struct MabHvf) * (number_of_hvfs);
    return result;
}