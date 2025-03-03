//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_BLOOM_FILTER_H
#define LOADABLE_KERNEL_MODULE_BLOOM_FILTER_H
#include <asm-generic/int-ll64.h>
struct BloomFilter {
    u32 bitset_mask; // bitset mask can be 31 represent for 32 bit - bitset can be 63 represent for 63 bit
    u32 hash_seed; // hash seed
    u32 aligned_u32_count; // number of u32 values in this array
    u32 number_of_hash_functions; // number of hash functions
    unsigned char* bitset; // bloom filter bitset and how to assign it
    u32 bf_effective_bits; // the effective bits in bloom filter
    u32 bf_effective_bytes; // the effective bytes in bloom filter, it should be calculated while in the bloom filter params setting
};

struct BloomFilter* init_bloom_filter(u32 effective_bits, u32 hash_seed, u32 number_of_hash_functions); // 进行布隆过滤器的初始化

struct BloomFilter* copy_bloom_filter(struct BloomFilter* bloom_filter); // 进行布隆过滤器的拷贝

void reset_bloom_filter(struct BloomFilter* old_bloom_filter); // 进行布隆过滤器的重置

void delete_bloom_filter(struct BloomFilter* bf); // 进行布隆过滤器内部分配的内存的删除

u32 bloom_hash_function(struct BloomFilter* bloom, void* value, u32 value_size, u32 index); // 布隆过滤器哈希函数

void push_element_into_bloom_filter(struct BloomFilter* bloom, void* value, u32 value_size); // 将元素放入布隆过滤器之中

void push_elements_into_bloom_filter(struct BloomFilter* bloom, int length, int* value); // 将一系列元素放入布隆过滤器之中

int check_element_in_bloom_filter(struct BloomFilter* bloom, void* value, u32 value_size); // 检查元素是否在布隆过滤器之中

void test_bloom_filter(void); // 进行测试
#endif //LOADABLE_KERNEL_MODULE_BLOOM_FILTER_H
