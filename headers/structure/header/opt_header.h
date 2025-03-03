//
// Created by 张贺凡 on 2024/12/9.
//
#include <net/ip.h>
#include "structure/crypto/crypto_structure.h"
#include "structure/header/common_part.h"

#ifndef PATH_VALIDATION_MODULE_OPT_HEADER_H
#define PATH_VALIDATION_MODULE_OPT_HEADER_H
// 定义 SESSION_ID 部分的长度
#define SESSION_ID_LENGTH 16
#define HASH_LENGTH 16
#define PVF_LENGTH 16
#define ENC_PVF_LENGTH 16
#define PVF_HASH_LENGTH 32
#define OPV_LENGTH 16

// first packet 包含的部分
// 1. OptHeader
// 2. SessionId
// 3. Path


// data packet 包含的部分
// 1. OptHeader
// 2. DataHash
// 3. SessionId
// 4. Timestamp
// 5. PVF
// 6. OPVs



struct OptHeader {
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
    __u16 dest;             // 目的节点编号 字段9
    __u16 hdr_len;          // 头部长度
    __u16 tot_len;          // 总长度
    __sum16 check;          // 校验和
    __u16 current_path_index;  // 当前路径索引
    unsigned char data[0];  // 额外的部分
};

// OPT PVF
struct OptPvf {
    char data[16];
};

// OPT OPV
struct OptOpv {
    char data[16];
};

// 从 skb 之中获取 opt_header
static inline struct OptHeader *opt_hdr(const struct sk_buff *skb) {
    return (struct OptHeader *) skb_network_header(skb);
}


// 获取 opt 数据包的每一个字段
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char *get_other_opt_hash_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader);
}

static inline unsigned char *get_other_opt_session_id_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader) +
           sizeof(struct DataHash);
}

static inline unsigned char *get_other_opt_timestamp_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}

static inline unsigned char *get_other_opt_pvf_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

static inline unsigned char *get_other_opt_opv_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct OptPvf);
}

// ------------------------------------------------------------------------------------------------------------

unsigned char *calculate_opt_hash(struct shash_desc *hash_api, struct OptHeader *opt_header);

void PRINT_OPT_HEADER(struct OptHeader *opt_header);

#endif //PATH_VALIDATION_MODULE_OPT_HEADER_H
