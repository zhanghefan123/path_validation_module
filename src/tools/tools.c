//
// Created by kernel-dbg on 24-1-31.
//
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <net/sch_generic.h>
#include "tools/tools.h"
#include "api/ftrace_hook_api.h"

int get_output_queue_length(struct net_device* dev){
    int output_queue_length;
    rcu_read_lock();
    struct Qdisc* qdisc = rcu_dereference(dev->qdisc);
    output_queue_length = qdisc_qlen_sum(qdisc);
    rcu_read_unlock();
    return output_queue_length;
}

/**
 * log_with_prefix 带有前缀的输出
 * @param msg 用户想要输出的消息
 * @return 不进行返回
 */
void LOG_WITH_PREFIX(char* msg){
    const char* prefix = LOG_PREFIX;
    size_t prefix_length = strlen(prefix);
    size_t msg_length = strlen(msg);
    size_t total_length = prefix_length + msg_length + 2;
    char total_msg[total_length];
    memcpy(total_msg, prefix, prefix_length);
    memcpy(total_msg + prefix_length, msg, msg_length);
    total_msg[total_length - 2] = '\n';
    total_msg[total_length - 1] = '\0';
    printk(KERN_EMERG "%s", total_msg);
}

/**
 * 进行有边框的输出用户想要输出的信息
 * @param msg 用户想要输出的信息
 */
void LOG_WITH_EDGE(char* msg){
    char final_output_msg[101];
    int length_of_msg = (int)strlen(msg);
    int length_of_each_edge = (100 - length_of_msg) / 2;
    memset(final_output_msg, (int)('-'), length_of_each_edge);
    final_output_msg[length_of_each_edge] = '\0';
    strcat(final_output_msg, msg);
    memset(final_output_msg + strlen(final_output_msg), (int)('-'), 100-strlen(final_output_msg));
    final_output_msg[100] = '\0';
    LOG_WITH_PREFIX(final_output_msg);
}

/**
 * 进行 ip 地址的打印
 * @param addr ip 地址
 */
void print_ipv4_address(__be32 addr){
    printk(KERN_EMERG "address = %pI4", &addr);
}

/**
 * 检查是否成功解析了函数的指针
 * @param pointer 指针
 * @param function_name 函数名称
 * @return
 */
bool TEST_RESOLVED(void* pointer, const char* function_name){
    if(pointer != NULL){
        char result[50];
        sprintf(result, "%s resolved", function_name);
        LOG_WITH_PREFIX(result);
        return true;
    } else {
        char result[50];
        sprintf(result, "%s not resolved", function_name);
        LOG_WITH_PREFIX(result);
        return false;
    }
}

/**
 * 进行众多函数地址的解析, 解析的结果放到 functions 之中
 * @param functions 存放解析后的函数指针
 * @param function_names 函数的名称
 * @param length 总共要解析的函数
 * @return
 */
bool resolve_functions_addresses(void** functions, char** function_names, int length){
    int index;
    bool resolve_result;
    for(index = 0; index < length; index ++){
        functions[index] = get_function_address(function_names[index]);
        resolve_result = TEST_RESOLVED(functions[index], function_names[index]);
        if(!resolve_result){
            printk(KERN_EMERG "cannot resolve function %s\n", function_names[index]);
            return resolve_result;
        }
    }
    return resolve_result;
}


/**
 * 进行 u32 的逐个 bit 的打印
 * @param n 打印的 u32 类型值
 */
void printk_binary_u32(u32 n) {
    int i;
    printk(KERN_EMERG "[zeusnet's kernel info]:binary: ");
    for(i = 0; i<=31; i++){
        // KERN_CONT 代表的是继续打印在一行内的说明
        printk(KERN_CONT KERN_EMERG "%c", (n&(1ul<<i)?'1':'0'));
    }
}

/**
 * 进行 u8 的逐个 bit 的打印
 * @param n 打印的 u8 类型值
 */
void printk_binary_u8(u8 n){
    int i;
    printk(KERN_EMERG "[zeusnet's kernel info]:binary: ");
    for(i = 0; i<=7; i++){
        printk(KERN_CONT KERN_EMERG "%c", (n&(1ul<<i)?'1':'0'));
    }
    printk(KERN_EMERG "\n");
}


/**
 * 打印 hash 或者 hmac 的输出
 * @param output 输出的内容
 * @param length 输出的长度
 */
void print_memory_in_hex(unsigned char* output, int length){
    int i;
    printk(KERN_CONT "RESULT ");
    for (i = 0; i < length; i++)
        printk(KERN_CONT "%02x", output[i]);
    printk(KERN_CONT "\n");
}

/**
 * 进行内存的相或
 * @param source 内存的源
 * @param target 内存的目的
 * @param length 长度
 */
void memory_or(unsigned char* source, unsigned char* target, int length){
    int index;
    for(index = 0; index < length; index++){
        source[index] = source[index] | target[index];
    }
}


/**
 *
 * @param source
 * @param target
 * @param length
 */
void memory_xor(unsigned char* target, const unsigned char* source, int length){
    int index;
    for(index = 0; index < length; index++){
        target[index] = target[index] ^ source[index];
    }
}


/**
 *
 * @param first
 * @param second
 * @param length
 * @return
 */
bool memory_compare(const unsigned char* first, const unsigned char* second, int length){
    int index;
    bool same = true;
    for(index = 0; index < length; index++){
        if(first[index] != second[index]){
            same = false;
            break;
        }
    }
    return same;
}
