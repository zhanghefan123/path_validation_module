//
// Created by zhf on 2025/12/9.
//

#ifndef PATH_VALIDATION_MODULE_ATLAS_HEADER_H
#define PATH_VALIDATION_MODULE_ATLAS_HEADER_H
#include <linux/list.h>
#include <linux/ip.h>
#include "structure/header/opt_header.h"
#include "structure/header/atlas_header.h"
#include "structure/routing/array_based_multipath_table.h"
#include "structure/path_validation_structure.h"

// atlas header
// -----------------------------------------------------------------


#define ATLAS_TAG_SIZE 3
#define ATLAS_END_TAG_SIZE 3
#define TYPE_IDENTIFIER_LENGTH 1

struct AtlasHeader{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4, version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
    #error	"Please fix <asm/byteorder.h>"
#endif
    __u8 tos;            // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __u16 source;           // 源节点编号 字段8
    __u16 dest;             // 目的节点编号 字段9
    __u16 hdr_len;            // 头部总长度 字段10
    __u16 tot_len;            // 总的长度 字段11
    __u16 length_of_path;     // 路径长度 字段12
    __sum16 check;          // 校验和 字段7
    __u16 current_path_index; // 当前索引 字段13
    unsigned char data[0];  // 额外的部分 (这里是指的 bf 的 bitarray)
};


static inline struct AtlasHeader* atlas_hdr(const struct sk_buff* skb){
    return (struct AtlasHeader*)(skb_network_header(skb));
}


// -----------------------------------------------------------------

// 获取 atlas 数据包的每一个字段
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char *get_other_atlas_hash_start_pointer(struct AtlasHeader *atlas_header) {
    return (unsigned char *) (atlas_header) +
           sizeof(struct AtlasHeader);
}

static inline unsigned char *get_other_atlas_session_id_start_pointer(struct AtlasHeader *atlas_header) {
    return (unsigned char *) (atlas_header) +
           sizeof(struct AtlasHeader) +
           sizeof(struct DataHash);
}

static inline unsigned char *get_other_atlas_timestamp_start_pointer(struct AtlasHeader *atlas_header) {
    return (unsigned char *) (atlas_header) +
           sizeof(struct AtlasHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}
// ------------------------------------------------------------------------------------------------------------


unsigned char *calculate_atlas_hash(struct shash_desc *hash_api, struct AtlasHeader *atlas_header);

#endif //PATH_VALIDATION_MODULE_ATLAS_HEADER_H
