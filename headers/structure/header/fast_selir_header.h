//
// Created by zhf on 2025/1/3.
//

#ifndef PATH_VALIDATION_MODULE_FAST_SELIR_HEADER_H
#define PATH_VALIDATION_MODULE_FAST_SELIR_HEADER_H
#include <net/ip.h>
#include "structure/header/selir_header.h"

struct FastSELiRHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4, version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 tos;               // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __u16 source;           // 源节点编号 字段8
    __u16 hdr_len;          // 头部总长度 字段9
    __u16 tot_len;          // 总的长度 字段10
    __u16 ppf_len;          // ppf长度 字段11
    __u16 dest_len;         // 目的节点个数 字段12
    __sum16 check;          // 校验和 字段7
};

static inline struct FastSELiRHeader *fast_selir_hdr(const struct sk_buff *skb) {
    return (struct FastSELiRHeader *) (skb_network_header(skb));
}

unsigned char* calculate_fast_selir_hash(struct shash_desc* hash_api, struct FastSELiRHeader* fast_selir_header);

struct EncPvf {
    char data[16];
};

// 获取各个字段的指针
// 标准头部 -> DataHash -> SessionID -> TimeStamp -> SELiRPvf -> EncPvf -> Destinations
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char *get_fast_selir_hash_start_pointer(struct FastSELiRHeader *fast_selir_header) {
    return (unsigned char *) (fast_selir_header) +
           sizeof(struct FastSELiRHeader);
}

static inline unsigned char *get_fast_selir_session_id_start_pointer(struct FastSELiRHeader *fast_selir_header) {
    return (unsigned char *) (fast_selir_header) +
           sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash);
}

static inline unsigned char *get_fast_selir_timestamp_start_pointer(struct FastSELiRHeader *fast_selir_header) {
    return (unsigned char *) (fast_selir_header) +
           sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}

static inline unsigned char *get_fast_selir_pvf_start_pointer(struct FastSELiRHeader *fast_selir_header) {
    return (unsigned char *) (fast_selir_header) +
           sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

static inline unsigned char* get_fast_selir_enc_pvf_start_pointer(struct FastSELiRHeader* fast_selir_header) {
    return (unsigned char*)(fast_selir_header) +
           sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf);
}

static inline unsigned char *get_fast_selir_ppf_start_pointer(struct FastSELiRHeader *fast_selir_header) {
    return (unsigned char *) (fast_selir_header) +
           sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf) +
           sizeof(struct EncPvf);
}

static inline unsigned char *get_fast_selir_dest_start_pointer(struct FastSELiRHeader *fast_selir_header, int ppf_length) {
    return (unsigned char *) (fast_selir_header) +
           sizeof(struct FastSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf) +
           sizeof(struct EncPvf) +
           ppf_length;
}
// ------------------------------------------------------------------------------------------------------------

#endif //PATH_VALIDATION_MODULE_FAST_SELIR_HEADER_H
