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
    printk(KERN_EMERG "\n"); // 不然可能不会进行输出
}

/**
 * 进行内存的相或
 * @param source 内存的源
 * @param target 内存的目的
 * @param length 长度
 */
void memory_or(unsigned char* target, unsigned char* source, int length){
    int index;
    for(index = 0; index < length; index++){
        target[index] = target[index] | source[index];
    }
}


/**
 *
 * @param source
 * @param target
 * @param length
 */
void memory_xor(unsigned char* target, unsigned char* source, int length){
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

bool memory_compare_ints(const int* first, const int * second, int length){
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

bool corrupt_decision(int start_scaled, int end_scaled) {
    const uint32_t MAX_SCALE = 1000000;

    // 1. 获取 0 ~ MAX_SCALE 的随机数
    // 注意：在 Linux v6.1+ 中推荐使用 get_random_u32_below()
    // 如果你的内核版本较老（例如 5.x），请替换为：prandom_u32_max(MAX_SCALE + 1)
    uint32_t r1 = prandom_u32_max(MAX_SCALE + 1);
    uint32_t r2 = prandom_u32_max(MAX_SCALE + 1);

    // 2. 计算差值（有符号 64 位，防止递减丢包率时下溢出）
    int64_t diff = (int64_t)end_scaled - (int64_t)start_scaled;

    // 3. 安全的内核态 64 位除法
    // 绝对不能直接写 (diff * r1) / MAX_SCALE，必须使用内核提供的 div_s64 宏
    int32_t offset = (int32_t)div_s64(diff * r1, MAX_SCALE);

    uint32_t current_rate = start_scaled + offset;

    // 4. 丢包判断
    return r2 < current_rate;
}

void test_corrupt(void){
    int start = 100000;
    int end   = 200000;
    int total = 1000000;
    int count = 0;
    int index;
    uint32_t pct_x100; // 放大 100 倍的百分比，例如 123 表示 1.23%

    printk(KERN_EMERG "==== TEST START 1%% END 5%%====\n");
    for (index = 0; index < total; index++) {
        if (corrupt_decision(start, end)) {
            count++;
        }
    }

    // 计算百分比并放大 100 倍以保留两位小数 (count / total * 100 * 100)
    // 相当于计算 (count * 10000) / total
    // 强制转型为 uint64_t 防止 count * 10000 溢出 32 位
    pct_x100 = div_u64((uint64_t)count * 10000, total);

    // 打印时，手动拆解出整数部分和两位小数部分
    printk(KERN_EMERG "result: %u.%02u%%\n", pct_x100 / 100, pct_x100 % 100);

    // -------------- 下一轮测试 --------------
    start = 50000;
    end   = 50000;
    count = 0;

    printk(KERN_EMERG "==== TEST START 5%% END 5%%====\n");
    for (index = 0; index < total; index++) {
        if (corrupt_decision(start, end)) {
            count++;
        }
    }

    pct_x100 = div_u64((uint64_t)count * 10000, total);
    printk(KERN_EMERG "result: %u.%02u%%\n", pct_x100 / 100, pct_x100 % 100);
}

u64 ktime_get_us(void){
    ktime_t now = ktime_get();
    u64 now_us = ktime_to_us(now);
    return now_us;
}


int uniform_sample_index(unsigned int number_of_sample_nodes)
{
    unsigned int rand_val;
    unsigned int index;

    // 边界保护：数组长度不能小于 1
    if (number_of_sample_nodes < 1)
        return 0;

    // 内核安全获取 32 位无符号随机数
    get_random_bytes(&rand_val, sizeof(rand_val));

    // 核心：均匀映射到 [0, a-1]（取模实现均匀抽样）
    index = rand_val % number_of_sample_nodes;

    return (int)(index);
}

void test_uniform_sample_index(void){
    int i;
    unsigned int idx;
    unsigned int arr_len;
    unsigned int *count_arr;  // Array to count occurrences of each index

    /* ===================== Test 1: Boundary Cases ===================== */
    pr_info("\n======== Test 1: Boundary Conditions ========\n");

    // Test array length = 0 (invalid) → should return 0
    idx = uniform_sample_index(0);
    pr_info("Array length 0 → index: %u (expected: 0)\n", idx);

    // Test array length = 1 (only valid index is 0)
    idx = uniform_sample_index(1);
    pr_info("Array length 1 → index: %u (expected: 0)\n", idx);

    /* ===================== Test 2: Index Validity ===================== */
    pr_info("\n======== Test 2: Index Validity Check ========\n");
    arr_len = 15;  // Indices must be in [0, 14]
    for (i = 0; i < 1000; i++) {
        idx = uniform_sample_index(arr_len);
        if (idx >= arr_len) {
            pr_err("ERROR: Invalid index %u (array length %u)\n", idx, arr_len);
            return;
        }
    }
    pr_info("1000 samples: All indices are valid in [0, %u]\n", arr_len - 1);

    /* ===================== Test 3: Uniformity Test ===================== */
    pr_info("\n======== Test 3: Uniformity Statistics ========\n");
    arr_len = 10;  // Test with array length 10 (indices 0~9)

    // Allocate and zero-initialize memory for counting
    count_arr = kzalloc(arr_len * sizeof(unsigned int), GFP_KERNEL);
    if (!count_arr) {
        pr_err("Memory allocation failed\n");
        return;
    }

    // Generate samples and count occurrences
    for (i = 0; i < TEST_SAMPLE_COUNT; i++) {
        idx = uniform_sample_index(arr_len);
        count_arr[idx]++;
    }

    // Print test results
    pr_info("Array length: %u | Total samples: %d\n", arr_len, TEST_SAMPLE_COUNT);
    for (i = 0; i < arr_len; i++) {
        pr_info("index %2u : %5u occurrences\n", i, count_arr[i]);
    }

    // Clean up allocated memory
    kfree(count_arr);
    pr_info("\n======== All Tests Completed ========\n");
}
