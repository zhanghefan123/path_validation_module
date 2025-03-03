//
// Created by zhf on 2024/12/6.
//

#ifndef PATH_VALIDATION_MODULE_ICING_HEADER_H
#define PATH_VALIDATION_MODULE_ICING_HEADER_H

#include <linux/byteorder/little_endian.h>
#include <net/ip.h>
#include "structure/crypto/crypto_structure.h"

#define ICING_PROOF_LENGTH 16

struct ICINGHeader {
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

struct ICINGHop {
    __u32 useless1; // 无用部分
    __u32 useless2; // 无用部分
    __u32 useless3; // 无用部分
    __u32 useless4; // 无用部分
    __u32 node_id; // 实际上是存储 node_id (20 bytes), 这里简化了只用一个
    __u32 link_id; // 实际上是存储 tag, 这里我们存储 link identifier
};

struct Expire {
    unsigned char data[2]; // 2 bytes expire
};

struct ICINGProof {
    unsigned char data[16]; // 12 bytes proof and 4 bytes hardener
};


static inline struct ICINGHeader *icing_hdr(const struct sk_buff *skb) {
    return (struct ICINGHeader *) skb_network_header(skb);
}

static inline unsigned char* get_icing_path_start_pointer(struct ICINGHeader* icing_header){
    return (unsigned char*)(icing_header) + sizeof(struct ICINGHeader);
}

static inline unsigned char* get_icing_proof_start_pointer(struct ICINGHeader* icing_header){
    return (unsigned char*)(icing_header) + sizeof(struct ICINGHeader) + icing_header->length_of_path * sizeof(struct ICINGHop) + icing_header->length_of_path * sizeof(struct Expire);
}

unsigned char* calculate_icing_hash(struct shash_desc* hash_api, struct ICINGHeader* icing_header);

void PRINT_ICING_HEADER(struct ICINGHeader* icing_header);


#endif //PATH_VALIDATION_MODULE_ICING_HEADER_H
