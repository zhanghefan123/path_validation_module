#ifndef PATH_VALIDATION_MODULE_MULTICAST_OPT_HEADER_H
#define PATH_VALIDATION_MODULE_MULTICAST_OPT_HEADER_H

#include <net/ip.h>
#include "structure/crypto/crypto_structure.h"
#include "structure/header/opt_header.h"

struct MulticastOptHeader{
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
    __u16 dest_len;         // 目的节点的数量
    __sum16 check;          // 校验和
    __u16 current_path_index;  // 当前路径索引
    unsigned char data[0];  // 额外的部分
};

// 通过 skb 进行头的获取
static inline struct MulticastOptHeader* multicast_opt_hdr(const struct sk_buff* skb){
    return (struct MulticastOptHeader*)(skb_network_header(skb));
}

// 获取 multicast opt 数据包的每一个字段
static inline unsigned char *get_multicast_opt_hash_start_pointer(struct MulticastOptHeader *multicast_opt_header) {
    return (unsigned char *) (multicast_opt_header) +
           sizeof(struct MulticastOptHeader);
}

static inline unsigned char *get_multicast_opt_session_id_start_pointer(struct MulticastOptHeader *multicast_opt_header) {
    return (unsigned char *) (multicast_opt_header) +
           sizeof(struct MulticastOptHeader) +
           sizeof(struct DataHash);
}

static inline unsigned char *get_multicast_opt_timestamp_start_pointer(struct MulticastOptHeader *multicast_opt_header) {
    return (unsigned char *) (multicast_opt_header) +
           sizeof(struct MulticastOptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}

static inline unsigned char *get_multicast_opt_pvf_start_pointer(struct MulticastOptHeader *multicast_opt_header) {
    return (unsigned char *) (multicast_opt_header) +
           sizeof(struct MulticastOptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

static struct OptOpv * get_multicast_opt_opv_start_pointer(struct MulticastOptHeader *multicast_opt_header) {
    return (struct OptOpv *) ((unsigned char*)(multicast_opt_header) +
           sizeof(struct MulticastOptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct OptPvf));
}


// 进行哈希计算的函数
unsigned char *calculate_multicast_opt_hash(struct shash_desc *hash_api, struct MulticastOptHeader *multicast_opt_header);









#endif