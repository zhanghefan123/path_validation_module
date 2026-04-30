#ifndef PATH_VALIDATION_MODULE_SEC_PATH_MAB_ACK_HEADER_H
#define PATH_VALIDATION_MODULE_SEC_PATH_MAB_ACK_HEADER_H

#include <net/ip.h>
#include "structure/header/sec_path_mab_common.h"

#define ACK_VALIDATION_PART_SIZE 20

struct SecPathMabAckHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4, version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u16 identifier;
    __u16 epoch;             // epoch
    __u8 tos;               // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __u16 source;           // 源节点编号 字段8
    __u16 dest;             // 目的节点编号 字段9
    __u16 hdr_len;          // 头部长度 字段 10
    __u16 tot_len;          // 总长度 字段 11
    __u16 length_of_path; // 路径长度 字段 12
    __u16 current_path_index;  // 当前路径索引 字段 13
    __sum16 check;          // 校验和 字段 14
    unsigned char data[0];  // 额外的部分
};

struct SecPathMabAckValidationPart {
    unsigned char content[ACK_VALIDATION_PART_SIZE];
};

// find the current network header
static inline struct SecPathMabAckHeader *sec_path_mab_ack_hdr(const struct sk_buff *skb) {
    return (struct SecPathMabAckHeader *) (skb_network_header(skb));
}

// find the path part
static inline struct SecPathMabPathPart *
get_sec_path_mab_ack_path_part(struct SecPathMabAckHeader *sec_path_mab_ack_header) {
    return (struct SecPathMabPathPart *) ((unsigned char *) (sec_path_mab_ack_header) +
                                          sizeof(struct SecPathMabAckHeader));
}

// get the validation part S->R1->R2->R3->D length_of_path == 3
static inline struct SecPathMabAckValidationPart *
get_sec_path_mab_ack_validation_part(struct SecPathMabAckHeader *sec_path_mab_ack_header) {
    int path_part_size = sizeof(struct SecPathMabHopIdentifier) * (sec_path_mab_ack_header->length_of_path);
    return (struct SecPathMabAckValidationPart *) ((unsigned char *) (sec_path_mab_ack_header) +
                                                   sizeof(struct SecPathMabAckHeader) + path_part_size);
}

// get sec path mab header size
int get_sec_path_mab_ack_header_size(int length_of_path);

#endif