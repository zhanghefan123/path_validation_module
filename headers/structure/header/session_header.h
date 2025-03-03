//
// Created by zhf on 2025/1/5.
//

#ifndef PATH_VALIDATION_MODULE_SESSION_HEADER_H
#define PATH_VALIDATION_MODULE_SESSION_HEADER_H

#include <net/ip.h>
#include "structure/header/common_part.h"

struct SessionHeader {
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
    __u16 path_length;      // 路径长度
    unsigned char data[0];  // 额外的部分
};

// 在建立 session 的时候用上的 -> 代表每一跳
struct SessionHop {
    __u16 node_id; // 节点 id
    __u16 link_id; // 链路标识
};

// 从 skb 之中获取 session header
static inline struct SessionHeader *session_hdr(const struct sk_buff* skb){
    return (struct SessionHeader*) skb_network_header(skb);
}

// 获取包的每一个字段
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char *get_session_setup_session_id_pointer(struct SessionHeader *session_setup_header) {
    return (unsigned char *) (session_setup_header) + sizeof(struct SessionHeader);
}

static inline unsigned char *get_session_setup_schedule_path_start_pointer(struct SessionHeader *session_header) {
    return (unsigned char *) (session_header) +
           sizeof(struct SessionHeader) +
           sizeof(struct SessionID);
}
// ------------------------------------------------------------------------------------------------------------

#endif //PATH_VALIDATION_MODULE_SESSION_HEADER_H
