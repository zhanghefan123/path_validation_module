//
// Created by zhf on 2026/3/27.
//

#ifndef PATH_VALIDATION_MODULE_TABLE_COMMON_H
#define PATH_VALIDATION_MODULE_TABLE_COMMON_H

// 添加过程中的各种情况的定义
#define NULL_POINTER (-1)
#define ADD_SUCCESS 0
#define ALREADY_EXISTS 1
#define CANNOT_FIND_BUCKET 2

static inline void print_status(int status) {
    switch (status) {
        case NULL_POINTER:
            printk(KERN_INFO "Status: NULL_POINTER\n");
            break;
        case ADD_SUCCESS:
            printk(KERN_INFO "Status: ADD_SUCCESS\n");
            break;
        case ALREADY_EXISTS:
            printk(KERN_INFO "Status: ALREADY_EXISTS\n");
            break;
        case CANNOT_FIND_BUCKET:
            printk(KERN_INFO "Status: CANNOT_FIND_BUCKET\n");
            break;
        default:
            printk(KERN_INFO "Status: UNKNOWN_STATUS\n");
    }
}

#endif //PATH_VALIDATION_MODULE_TABLE_COMMON_H
