//
// Created by zhf on 2025/12/16.
//

#ifndef PATH_VALIDATION_MODULE_MULTICAST_SELIR_HEADER_H
#define PATH_VALIDATION_MODULE_MULTICAST_SELIR_HEADER_H
#include <net/ip.h>
#include "structure/header/opt_header.h"
#include "structure/header/fast_selir_header.h"
struct MulticastSelirHeader {
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

// 通过 skb 进行头部的获取
static inline struct MulticastSelirHeader *multicast_selir_hdr(const struct sk_buff* skb){
    return (struct MulticastSelirHeader*)(skb_network_header(skb));
}

unsigned char* calculate_multicast_selir_hash(struct shash_desc* hash_api, struct MulticastSelirHeader* multicast_selir_header);

// 进行各个指针的获取
// hash
static inline unsigned char *get_multicast_selir_hash_start_pointer(struct MulticastSelirHeader *multicast_selir_header) {
    return (unsigned char *) (multicast_selir_header) +
           sizeof(struct MulticastSelirHeader);
}

// session id
static inline unsigned char* get_multicast_selir_session_id_start_pointer(struct MulticastSelirHeader *multicast_selir_header) {
    return (unsigned char *) (multicast_selir_header) +
           sizeof(struct MulticastSelirHeader) +
           sizeof(struct DataHash);
}

// timestamp
static inline unsigned char *get_multicast_selir_timestamp_start_pointer(struct MulticastSelirHeader *multicast_selir_header) {
    return (unsigned char *) (multicast_selir_header) +
           sizeof(struct MulticastSelirHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}

// pvf
static inline unsigned char *get_multicast_selir_pvf_start_pointer(struct MulticastSelirHeader *multicast_selir_header) {
    return (unsigned char *) (multicast_selir_header) +
           sizeof(struct MulticastSelirHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

// envpvfs
static inline unsigned char* get_multicast_selir_enc_pvf_start_pointer(struct MulticastSelirHeader* multicast_selir_header){
    return (unsigned char*) (multicast_selir_header) +
           sizeof(struct MulticastSelirHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf);
}

// ppf
static inline unsigned char *get_multicast_selir_ppf_start_pointer(struct MulticastSelirHeader *multicast_selir_header, int number_of_destinations) {
    return (unsigned char *) (multicast_selir_header) +
           sizeof(struct MulticastSelirHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf) +
           sizeof(struct EncPvf) * number_of_destinations;
}

#endif //PATH_VALIDATION_MODULE_MULTICAST_SELIR_HEADER_H
