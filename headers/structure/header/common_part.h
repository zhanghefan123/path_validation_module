//
// Created by 张贺凡 on 2024/12/16.
//

#ifndef PATH_VALIDATION_MODULE_COMMON_PART_H
#define PATH_VALIDATION_MODULE_COMMON_PART_H
#include <net/ip.h>
// DataHash
struct DataHash {
    uint64_t first_part; // 8 字节
    uint64_t second_part; // 8 字节
};

// 会话 id
struct SessionID {
    uint64_t first_part;  // 8 字节
    uint64_t second_part; // 8 字节
};

// 时间戳
struct TimeStamp {
    char data[8];
};

#endif //PATH_VALIDATION_MODULE_COMMON_PART_H
