#ifndef PATH_VALIDATION_MODULE_SEC_PATH_MAB_HEADER_H
#define PATH_VALIDATION_MODULE_SEC_PATH_MAB_HEADER_H

#include <net/ip.h>
#include "common_part.h"
#include "structure/crypto/crypto_structure.h"
#include "structure/header/sec_path_mab_common.h"

#define ACK_AUTHENTICATION_LENGTH 20

struct SecPathMabHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4, version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u16 identifier;       // 数据包的id
    __u16 epoch;            // epoch 字段2
    __u8 tos;               // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __u16 source;           // 源节点编号 字段8
    __u16 dest;             // 目的节点编号 字段9
    __u16 hdr_len;          // 头部长度 字段 10
    __u16 tot_len;          // 总长度 字段 11
    __u16 length_of_path; // 路径长度 字段 12
    __u16 current_path_index;  // 当前路径索引 字段 13
    __sum16 check;          // 校验和 字段 14
    unsigned char data[0];  // 额外的部分
};

// SecPathMab PVF
struct MabPvf {
    char data[16];
};

// SecPathMab HVF
struct MabHvf {
    char data[16];
};

// verification result
struct VerificationResult {
    int rcv_packet_type;
    unsigned char *sample_identifier;
};

// Packet type
#define RCV_DATA_PACKET 0
#define RCV_SAMPLE_PACKET 1
#define RCV_ERROR_PACKET 2

// SecPathMab Metadata
struct SecPathMabMetadata {
    struct DataHash datahash;
    struct TimeStamp timestamp;
};

// SecPathMab ValidationPart
struct SecPathMabValidationPart {
    struct MabPvf pvf;
    struct MabHvf hvfs[0];
};


// 从 skb 之中获取 sec_path_mab_header
static inline struct SecPathMabHeader *sec_path_mab_hdr(const struct sk_buff *skb) {
    return (struct SecPathMabHeader *) skb_network_header(skb);
}


// packet format: metadata{hash, ts} --> path part --> pvf --> hvf1,...hvfn

// FUNC1: retrieve the metadata
static inline struct SecPathMabMetadata *get_sec_path_mab_metadata(struct SecPathMabHeader *sec_path_mab_header) {
    return (struct SecPathMabMetadata *) ((unsigned char *) (sec_path_mab_header) + sizeof(struct SecPathMabHeader));
}

// FUNC2: retrieve the path part
static inline struct SecPathMabPathPart *get_sec_path_mab_path_part(struct SecPathMabHeader *sec_path_mab_header) {
    return (struct SecPathMabPathPart *) ((unsigned char *) (sec_path_mab_header) + sizeof(struct SecPathMabHeader) +
                                          sizeof(struct SecPathMabMetadata));
}

// FUNC3: retrieve the validation part
static inline struct SecPathMabValidationPart *
get_sec_path_mab_validation_part(struct SecPathMabHeader *sec_path_mab_header, int number_of_hop_identifiers) {
    return (struct SecPathMabValidationPart *) ((unsigned char *) (sec_path_mab_header)
                                                + sizeof(struct SecPathMabHeader)
                                                + sizeof(struct SecPathMabMetadata)
                                                + sizeof(struct SecPathMabHopIdentifier) * number_of_hop_identifiers);
}


unsigned char *calculate_sec_path_mab_hash(struct shash_desc *hash_api, struct SecPathMabHeader *mab_header, struct TimeStamp* timestamp);

int get_sec_path_mab_header_size(int number_of_hop_identifiers, int number_of_hvfs);
#endif