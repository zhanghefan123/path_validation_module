#ifndef PATH_VALIDATION_MODULE_EPIC_SESSION_HEADER_H
#define PATH_VALIDATION_MODULE_EPIC_SESSION_HEADER_H
#include <net/ip.h>
#include "structure/header/epic_header.h"
#include "structure/header/epic_fields_length.h"



struct EpicSessionHeader {
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
        __u16 length_of_path;      // 路径长度
        __sum16 check;          // 校验和
        __u16 current_path_index;  // 当前路径索引
        unsigned char data[0];  // 额外的部分
};


// 用来存储 sigma_{i}
struct EpicHopAuthenticator {
    unsigned char data[16];
};


// 从 skb 之中获取 epic_session_header
static inline struct EpicSessionHeader* epic_session_hdr(const struct sk_buff* skb) {
    return (struct EpicSessionHeader*) skb_network_header(skb);
}

// 获取包的每一个字段 PATH_TIME_STAMP || HI ... || sigma ...
// ------------------------------------------------------------------------------------------------------------
static inline unsigned char* get_epic_session_setup_timestamp_pointer(struct EpicSessionHeader* epic_session_header){
    return (unsigned char*)(epic_session_header) +
           sizeof(struct EpicSessionHeader);
}

static inline struct EpicHopIdentifier* get_epic_session_setup_hop_identifiers_start_pointer(struct EpicSessionHeader* epic_session_header){
    return (struct EpicHopIdentifier*)((unsigned char*)(epic_session_header) +
            sizeof(struct EpicSessionHeader) + PATH_TIMESTAMP_LENGTH);
}

static inline struct EpicHopAuthenticator* get_epic_session_setup_hop_authenticator_start_pointer(struct EpicSessionHeader* epic_session_header){
    return (struct EpicHopAuthenticator*)((unsigned char*)(epic_session_header) +
           sizeof(struct EpicSessionHeader) + PATH_TIMESTAMP_LENGTH +
           epic_session_header->length_of_path * sizeof(struct EpicHopIdentifier));
}
// ------------------------------------------------------------------------------------------------------------

#endif