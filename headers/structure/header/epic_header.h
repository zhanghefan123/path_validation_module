
//
// Created by zhf on 2025/12/1.
//

#ifndef PATH_VALIDATION_MODULE_EPIC_HEADER_H
#define PATH_VALIDATION_MODULE_EPIC_HEADER_H
#include <net/ip.h>
#include "structure/crypto/crypto_structure.h"


struct EpicHeader{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4, version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
    #error	"Please fix <asm/byteorder.h>"
#endif
    __u8 tos;            // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __u16 source;           // 源节点编号 字段8
    __u16 dest;             // 目的节点编号 字段9
    __u16 hdr_len;            // 头部总长度 字段10
    __u16 tot_len;            // 总的长度 字段11
    __u16 length_of_path;     // 路径长度 字段12
    __u16 current_path_index; // 当前索引 字段13
    __sum16 check;          // 校验和 字段14
    unsigned char data[0];  // 额外的部分 (这里是指的 bf 的 bitarray)
};

// 路径部分相关结构体
// ------------------------------------------------------------------
// 1. path timestamp 路径时间戳 u64

// 2. EpicHopIdentifier 路径标识
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|r r r r r r I E|    ExpTime    |           ConsIngress         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        ConsEgress             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct EpicHopIdentifier{
    __u16 node_id;
    __u16 link_id;
    __u16 incoming_link_id;
    // 除去了 MAC 的部分
};

// 3. 组成部分
// PATH := (TSpath || SRC || DEST || HI1 || ... || HIl)
struct PathPartMeta {
    u64 path_time_stamp; // 路径时间戳
    u64 src; // 源占8字节
    u64 dest; // 目的占8字节
};

// 4. 路径部分
struct EpicPathPart {
    struct PathPartMeta path_part_meta; // 元数据
    struct EpicHopIdentifier hop_identifiers[0]; // hi list
};

void PRINT_EPIC_HOP_IDENTIFIER(struct EpicHopIdentifier* epic_hop_idetifier);
// ------------------------------------------------------------------

// 验证部分相关结构体
// ------------------------------------------------------------------
// destination validation field 目的节点验证字段
struct DestinationValidationField {
    unsigned char data[16];
};

// validationPartMeta 代表的是验证字段
struct ValidationPartMeta{
    // 数据包时间戳
    u64 packet_timestamp;
    // 目的节点验证字段
    struct DestinationValidationField destination_validation_field;
};


// segment identifier 占用2字节
struct SegmentIdentifier{
    unsigned char data[2];
};
// hop validation field 占用3字节
struct HopValidationField {
    unsigned char data[3];
};

// validation per hop
struct ValidationPerHop {
    struct SegmentIdentifier segment_identifier;
    struct HopValidationField hop_validation_field;
};

// VALHD = (tspkt || VSD || S1 || V1 || ... || Sl || Vl)
struct EpicValidationPart {
    struct ValidationPartMeta path_validation_meta;
    struct ValidationPerHop validationHops[0];
};

// ------------------------------------------------------------------

// 从 skb 之中提取 epic 首部
static inline struct EpicHeader *epic_hdr(const struct sk_buff* skb){
    return (struct EpicHeader*)(skb_network_header(skb));
}

// 获取路径起始部分
static inline struct EpicPathPart* get_epic_path_part_start_pointer(struct EpicHeader * epic_header){
//    printk(KERN_EMERG "epic_header: %d\n", sizeof(struct EpicHeader));
    return (struct EpicPathPart*)((unsigned char*)(epic_header) + sizeof(struct EpicHeader));
}


// 获取验证起始部分 S->R1->R2->R3->D 正常的情况下是进行 ->R1  ->R2 -> R3 ->D 的记录, 现在只需要记录 ->R1-> ->R2-> ->R3->
static inline struct EpicValidationPart* get_epic_validation_part_start_pointer(struct EpicHeader * epic_header){
    int path_part_size = sizeof(struct PathPartMeta) + (epic_header->length_of_path - 1) * sizeof(struct EpicHopIdentifier);
    return (struct EpicValidationPart*)((unsigned char*)(epic_header) + sizeof(struct EpicHeader) + path_part_size);
}

void PRINT_EPIC_HEADER(struct EpicHeader* epic_header);
// 获取各个字段的指针

// 根据路径长度获取包头长度
int get_epic_header_size(int length_of_path);

// 获取路径部分的长度
int get_epic_header_path_part_size(int length_of_path);

// 获取验证部分的长度
int get_epic_header_validation_part_size(int length_of_path);

// 进行哈希的计算
unsigned char* calculate_epic_hash(struct shash_desc* hash_api, struct EpicHeader* epic_header);

#endif //PATH_VALIDATION_MODULE_EPIC_HEADER_H
