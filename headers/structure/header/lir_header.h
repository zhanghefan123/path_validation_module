//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H

#include <uapi/linux/types.h>
#include <linux/byteorder/little_endian.h>
#include <net/ip.h>


struct LiRHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4,version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8	tos;            // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __sum16 check;          // 校验和 字段7
    __u16 source;           // 源节点编号 字段8
    __u16 hdr_len;            // 头部总长度 字段9
    __u16 tot_len;            // 总的长度 字段10
    __u16 bf_len;             // 布隆过滤器长度 字段11
    __u16 dest_len;           // 目的节点个数 字段12
    unsigned char data[0];  // 额外的部分 (这里是指的 bf 的 bitarray)
};

static inline struct LiRHeader *lir_hdr(const struct sk_buff *skb) {
    return (struct LiRHeader *) skb_network_header(skb);
}

void PRINT_LIR_HEADER(struct LiRHeader* pvh);

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
