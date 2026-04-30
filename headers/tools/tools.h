#ifndef ZEUSNET_KERNEL_TOOLS_H
#define ZEUSNET_KERNEL_TOOLS_H
#include <net/route.h>
#define LOG_PREFIX "[zeusnet's kernel info]:"
#define TEST_SAMPLE_COUNT 100000  // Total samples for uniformity test

// 1. LOG 相关的 tools
void LOG_WITH_PREFIX(char* msg);
void LOG_WITH_EDGE(char* msg);
void printk_binary_u32(u32 n);
void printk_binary_u8(u8 n);
void print_memory_in_hex(unsigned char* output, int length);
void print_ipv4_address(__be32 addr);

// 2. 解析函数地址相关的 tools
bool TEST_RESOLVED(void* pointer, const char* function_name);
bool resolve_functions_addresses(void** functions, char** function_names, int length);

// 3. 内存相关的 tools
void memory_or(unsigned char* target, unsigned char* source, int length);
void memory_xor(unsigned char* target, unsigned char* source, int length);
bool memory_compare(const unsigned char* first, const unsigned char* second, int length);
bool memory_compare_ints(const int* first, const int * second, int length);

// 4. 进行队列长度的获取
int get_output_queue_length(struct net_device* dev);

// 5. 对数组之中的每个元素进行均匀的采样
int uniform_sample_index(unsigned int number_of_sample_nodes);
void test_uniform_sample_index(void);

// 5. 是否进行篡改
bool corrupt_decision(int start_scaled, int end_scaled);
void test_corrupt(void);
u64 ktime_get_us(void);
#endif
