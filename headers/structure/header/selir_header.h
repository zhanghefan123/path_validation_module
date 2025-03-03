//
// Created by 张贺凡 on 2024/12/11.
//

#ifndef PATH_VALIDATION_MODULE_SELIR_HEADER_H
#define PATH_VALIDATION_MODULE_SELIR_HEADER_H

#include <net/ip.h>
#include <uapi/linux/types.h>
#include <linux/byteorder/little_endian.h>
#include "structure/crypto/crypto_structure.h"
#include "structure/header/common_part.h"

struct SELiRInfo {
    // pvf 有效位数
    int pvf_effective_bits;
    // pvf 有效字节数
    int pvf_effective_bytes;
};

static inline struct SELiRInfo *init_selir_info(void) {
    return (struct SELiRInfo *) (kmalloc(sizeof(struct SELiRInfo), GFP_KERNEL));
}

static inline void free_selir_info(struct SELiRInfo *selir_info) {
    if (NULL != selir_info) {
        kfree(selir_info);
    }
}

struct SELiRHeader {
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

struct SELiRPvf {
    char data[16]; // 这里模仿的是 opt
};

// selir 数据包的结构
// data_packet header header / datahash / sessionid / timestamp / pvf_bitset / ppf_bitset /destinations

static inline struct SELiRHeader *selir_hdr(const struct sk_buff *skb) {
    return (struct SELiRHeader *) (skb_network_header(skb));
}

// 获取 pvf 起始指针
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char* get_enc_pvf_start_pointer(struct SELiRHeader* selir_header, int ppf_length){
    return (unsigned char*) (selir_header) +
            sizeof(struct SELiRHeader) +
            sizeof(struct DataHash) +
            sizeof(struct SessionID) +
            sizeof(struct TimeStamp) +
            sizeof(struct SELiRPvf) +
            ppf_length;
}

static inline unsigned char *get_selir_hash_start_pointer(struct SELiRHeader *selir_header) {
    return (unsigned char *) (selir_header) +
           sizeof(struct SELiRHeader);
}

static inline unsigned char *get_selir_session_id_start_pointer(struct SELiRHeader *selir_header) {
    return (unsigned char *) (selir_header) +
           sizeof(struct SELiRHeader) +
           sizeof(struct DataHash);
}

static inline unsigned char *get_selir_timestamp_start_pointer(struct SELiRHeader *selir_header) {
    return (unsigned char *) (selir_header) +
           sizeof(struct SELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}

static inline unsigned char *get_selir_pvf_start_pointer(struct SELiRHeader *selir_header) {
    return (unsigned char *) (selir_header) +
           sizeof(struct SELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

static inline unsigned char *get_selir_ppf_start_pointer(struct SELiRHeader *selir_header) {
    return (unsigned char *) (selir_header) +
           sizeof(struct SELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct SELiRPvf);
}
// ------------------------------------------------------------------------------------------------------------

unsigned char *calculate_selir_hash(struct shash_desc *hash_api, struct SELiRHeader *selir_header);

void PRINT_SELIR_HEADER(struct SELiRHeader *seh);

#endif // PATH_VALIDATION_MODULE_SELIR_HEADER_H
