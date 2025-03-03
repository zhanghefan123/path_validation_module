//
// Created by zhf on 2025/1/5.
//

#ifndef PATH_VALIDATION_MODULE_MULTICAST_SESSION_HEADER_H
#define PATH_VALIDATION_MODULE_MULTICAST_SESSION_HEADER_H

#include <net/ip.h>
#include "structure/header/common_part.h"

struct MulticastSessionHeader {
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
    __u16 link_identifiers_count;   // 链路标识的总数
    __u16 destination_count; // 目的节点的个数
    __u16 current_path_index;  // 当前路径索引
    unsigned char data[0];  // 额外的部分
};

static inline struct MulticastSessionHeader *multicast_session_hdr(const struct sk_buff *skb) {
    return (struct MulticastSessionHeader *) skb_network_header(skb);
}

// 获取数据包的每一个字段
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char *
get_multicast_session_setup_session_id_pointer(struct MulticastSessionHeader *session_setup_header) {
    return (unsigned char *) (session_setup_header) + sizeof(struct MulticastSessionHeader);
}

static inline unsigned char *
get_multicast_session_setup_link_identifiers_pointer(struct MulticastSessionHeader *session_header) {
    return (unsigned char *) (session_header) +
           sizeof(struct MulticastSessionHeader) +
           sizeof(struct SessionID);
}

static inline unsigned char* get_multicast_session_setup_destination_pointer(struct MulticastSessionHeader* session_header, int link_identifiers_count){
    return (unsigned char *) (session_header) +
           sizeof(struct MulticastSessionHeader) +
           sizeof(struct SessionID) +
           link_identifiers_count * sizeof(int);
}

static inline unsigned char *get_multicast_session_setup_actual_path_pointer(struct MulticastSessionHeader *session_header,
                                                                             int link_identifiers_count,
                                                                             int destinations_count) {
    return (unsigned char *) (session_header) +
           sizeof(struct MulticastSessionHeader) +
           sizeof(struct SessionID) +
           link_identifiers_count * sizeof(int) +
           destinations_count * sizeof(int);
}

// ------------------------------------------------------------------------------------------------------------

#endif //PATH_VALIDATION_MODULE_MULTICAST_SESSION_HEADER_H
