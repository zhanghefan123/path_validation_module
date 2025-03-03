#ifndef ZEUSNET_KERNEL_TOOLS_H
#define ZEUSNET_KERNEL_TOOLS_H
#include <net/route.h>
#define LOG_PREFIX "[zeusnet's kernel info]:"
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
void memory_or(unsigned char* source, unsigned char* target, int length);
void memory_xor(unsigned char* source, const unsigned char* target, int length);
bool memory_compare(const unsigned char* first, const unsigned char* second, int length);

// 4. 进行队列长度的获取
int get_output_queue_length(struct net_device* dev);
#endif
