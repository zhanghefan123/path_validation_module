//
// Created by zhf on 2025/12/15.
//

#ifndef PATH_VALIDATION_MODULE_MULTIPATH_SELIR_HEADER_H
#define PATH_VALIDATION_MODULE_MULTIPATH_SELIR_HEADER_H
#include <net/ip.h>
#include "structure/header/opt_header.h"
#include "structure/header/fast_selir_header.h"

struct MultipathSELiRHeader {
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
    __u16 max_path_length;  // 最大路径长度
    __u16 destination;      // 负责给多路径用的
    __u16 number_of_paths;   // 路径的数量
    __u16 selected_paths_part_size; // 选择的路线的大小
    __u16 current_path_index;  // 目的节点个数 字段12
    __sum16 check;          // 校验和 字段7
    unsigned char data[0];   // 其余部分
};

//  获取各个字段的指针
//  标准头部 -> datahash -> sessionid -> timestamp -> path -> hvf -> dvf1,2,3,-> ppf -> destinations

// hash
static inline unsigned char *get_multipath_selir_hash_start_pointer(struct MultipathSELiRHeader *multipath_selir_header) {
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader);
}

// session id
static inline unsigned char* get_multipath_selir_session_id_start_pointer(struct MultipathSELiRHeader *multipath_selir_header) {
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash);
}

// timestamp
static inline unsigned char *get_multipath_selir_timestamp_start_pointer(struct MultipathSELiRHeader *multipath_selir_header) {
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID);
}

// 这里可能需要加上一个选择的路径的数组
static inline unsigned char *get_possible_path_ids_start_pointer(struct MultipathSELiRHeader* multipath_selir_header){
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

// pvf
static inline unsigned char *get_multipath_selir_pvf_start_pointer(struct MultipathSELiRHeader *multipath_selir_header) {
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(unsigned char) * multipath_selir_header->selected_paths_part_size;
}

// dvfs
static inline unsigned char *get_multipath_selir_dvf_start_pointer(struct MultipathSELiRHeader *multipath_selir_header) {
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(unsigned char) * multipath_selir_header->selected_paths_part_size +
           sizeof(struct SELiRPvf);
}

// dvfi
static inline unsigned char *get_multipath_selir_ith_dvf_start_pointer(struct MultipathSELiRHeader *multipath_selir_header, int index) {
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(unsigned char) * multipath_selir_header->selected_paths_part_size +
           sizeof(struct SELiRPvf) +
           sizeof(struct EncPvf) * index;
}

// ppf
static inline unsigned char* get_multipath_selir_ppf_start_pointer(struct MultipathSELiRHeader* multipath_selir_header, int number_of_paths){
    return (unsigned char *) (multipath_selir_header) +
           sizeof(struct MultipathSELiRHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(unsigned char) * multipath_selir_header->selected_paths_part_size +
           sizeof(struct SELiRPvf) +
           sizeof(struct EncPvf) * number_of_paths;
}

static inline struct MultipathSELiRHeader* multipath_selir_hdr(const struct sk_buff* skb){
    return (struct MultipathSELiRHeader *) (skb_network_header(skb));
}

unsigned char* calculate_multipath_selir_hash(struct shash_desc* hash_api, struct MultipathSELiRHeader* multipath_selir_header);


#endif //PATH_VALIDATION_MODULE_MULTIPATH_SELIR_HEADER_H
