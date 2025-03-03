#include "structure/crypto/bloom_filter.h"
#include "tools/tools.h"
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <asm-generic/bitops/instrumented-atomic.h>
#include <asm-generic/bitops/instrumented-non-atomic.h>


/**
 * 进行布隆过滤器的初始化
 * @param effective_bits 有效的位数
 * @param hash_seed 哈希种子
 * @param number_of_hash_functions 哈希函数的个数
 */
struct BloomFilter *init_bloom_filter(u32 effective_bits, u32 hash_seed, u32 number_of_hash_functions) {
    // 进行内存的分配
    struct BloomFilter *created_bloom_filter = (struct BloomFilter *) kmalloc(sizeof(struct BloomFilter), GFP_KERNEL);
    // 设置 u32 个数
    created_bloom_filter->aligned_u32_count = 0x0;
    // 设置 effective_bits
    created_bloom_filter->bf_effective_bits = effective_bits;
    // 设置掩码
    created_bloom_filter->bitset_mask = effective_bits - 1;
    // 设置 effective_bytes
    created_bloom_filter->bf_effective_bytes = (effective_bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
    // 设置 bit set
    created_bloom_filter->bitset = (unsigned char *) kmalloc(
            sizeof(unsigned char) * created_bloom_filter->bf_effective_bytes, GFP_KERNEL);
    memset(created_bloom_filter->bitset, 0, created_bloom_filter->bf_effective_bytes);
    // 设置哈希种子
    created_bloom_filter->hash_seed = hash_seed;
    // 设置哈希函数个数
    created_bloom_filter->number_of_hash_functions = number_of_hash_functions;
    // 返回创建好的布隆过滤器
    return created_bloom_filter;
}

/**
 * 进行布隆过滤器的克隆，返回新的布隆过滤器
 * @param old_bloom_filter 想要进行克隆的布隆过滤器
 * @return 新创建出来的布隆过滤器
 */
struct BloomFilter *copy_bloom_filter(struct BloomFilter *old_bloom_filter) {
    // 创建一个新的布隆过滤器
    struct BloomFilter *new_bloom_filter = init_bloom_filter(old_bloom_filter->bf_effective_bits,
                                                             old_bloom_filter->hash_seed,
                                                             old_bloom_filter->number_of_hash_functions);
    // 拷贝数组
    memcpy(new_bloom_filter->bitset, old_bloom_filter->bitset, sizeof(unsigned char) * old_bloom_filter->bf_effective_bytes);
    // 返回新的布隆过滤器
    return new_bloom_filter;
}


/**
 * 进行布隆过滤器的重置，即将其中的二进制数组全部置为0
 * @param bloom_filter
 */
void reset_bloom_filter(struct BloomFilter *bloom_filter) {
    // 判断是否 bitset 不为空
    if (bloom_filter->bitset != NULL) {
        // 如果不为空, 调用 memset 刷 0
        memset(bloom_filter->bitset, 0, sizeof(unsigned char) * bloom_filter->bf_effective_bytes);
    }
}

/**
 * 进行布隆过滤器的释放
 * @param bf 要释放的 bf
 */
void delete_bloom_filter(struct BloomFilter *bf) {
    // 判断是否 bf 为 NULL
    if (bf != NULL) {
        // 判断 bit array 是否为 NULL
        if (bf->bitset != NULL) {
            // 进行释放
            kfree(bf->bitset);
            bf->bitset = NULL;
        }
        kfree(bf);
        LOG_WITH_PREFIX("delete bloom filter");
    } else {
        LOG_WITH_PREFIX("bloom filter is NULL");
    }
}

/**
 * 将一个传入的值首先通过hash函数映射到一个从 [0, bitset_mask-1] 的索引
 * @param bloom 布隆过滤器
 * @param value 要插入到布隆过滤器之中的值
 * @param value_size 值的大小 (字节)
 * @param random_value 随便取值
 * @return 从 [0, bitset_mask] 的索引, 所以一般取 31 63 这种
 */
u32 bloom_hash_function(struct BloomFilter *bloom, void *value, u32 value_size, u32 random_value) {
    u32 h; // hash value
    // if the value is aligned to 32 bits, use jhash2 如果总长度(bit) / 32 为整数
    if (bloom->aligned_u32_count) {
        h = jhash2(value, bloom->aligned_u32_count, bloom->hash_seed + random_value);
    }
        // if the value is not aligned to 32 bits, use jhash  如果总长度(bit) / 32 不为整数
    else {
        h = jhash(value, value_size, bloom->hash_seed + random_value);
    }
    return h % bloom->bitset_mask;
}

/**
 * 将一个值插入到布隆过滤器之中
 * @param bloom 布隆过滤器
 * @param value 要插入到布隆过滤器之中的值
 * @param value_size 值的大小 (字节)
 * @return void
 */
void push_element_into_bloom_filter(struct BloomFilter *bloom, void *value, u32 value_size) {
    u32 i;
    u32 hash;
    for (i = 0; i < bloom->number_of_hash_functions; i++) {
        hash = bloom_hash_function(bloom, value, value_size, i);
        set_bit(hash, (unsigned long*)(bloom->bitset));
    }
}


/**
 * 将元素列表放入布隆过滤器之中
 * @param bloom 布隆过滤器
 * @param length 要插入的数组的长度
 * @param value 值
 * @param value_size 值的大小 (字节)
 */
void push_elements_into_bloom_filter(struct BloomFilter *bloom, int length, int *value) {
    int index;
    for (index = 0; index < length; index++) {
        push_element_into_bloom_filter(bloom, &(value[index]), sizeof(int));
    }
}

/**
 * 将一个值插入到布隆过滤器之中
 * @param bloom 布隆过滤器
 * @param value 要检查的值
 * @param value_size 值的大小 (字节)
 * @return 如果元素可能被插入则返回0,如果元素没有插入则返回1
 */
int check_element_in_bloom_filter(struct BloomFilter *bloom, void *value, u32 value_size) {
    u32 i;
    u32 hash;
    for (i = 0; i < bloom->number_of_hash_functions; i++) {
        hash = bloom_hash_function(bloom, value, value_size, i);
        if (!test_bit(hash, (unsigned long*)(bloom->bitset))) {
            // 说明元素从来没有被插入过
            return 1;
        }
    }
    return 0; // 说明元素可能被插入过
}

void test_bloom_filter(void) {
    // 1. 创建变量
    int effective_bits = 32;
    int hash_seed = 0x12;
    int number_of_hash_functions = 0x05;
    // 2. 创建布隆过滤器
    struct BloomFilter *bloom_filter_tmp = init_bloom_filter(effective_bits, hash_seed, number_of_hash_functions);
    // 3. 开始进行测试
    // --------------------------------------------------------------------
    LOG_WITH_EDGE("start to test bloom filter");
    // 3.1 创建测试元素
    int index;
    char printBuffer[100];
    int first_insert_element = 0x5;
    int second_insert_element = 0x6;
    int third_not_insert_element = 0x7;
    int *allElements = (int *) kmalloc(sizeof(int) * 3, GFP_KERNEL);
    int *insertElements = (int *) kmalloc(sizeof(int) * 2, GFP_KERNEL);
    allElements[0] = first_insert_element;
    allElements[1] = second_insert_element;
    allElements[2] = third_not_insert_element;
    insertElements[0] = first_insert_element;
    insertElements[1] = second_insert_element;
    // 3.2 进行批量元素插入
    LOG_WITH_PREFIX("insert elements in batch");
    push_elements_into_bloom_filter(bloom_filter_tmp, 2, insertElements);
    // 3.3 进行元素的测试
    for (index = 0; index < 3; index++) {
        int checkElement = allElements[index];
        if (0 == check_element_in_bloom_filter(bloom_filter_tmp, &(checkElement), sizeof(checkElement))) {
            sprintf(printBuffer, "element %d in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        } else {
            sprintf(printBuffer, "element %d not in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        }
    }
    // 3.4 进行布隆过滤器的重置
    LOG_WITH_PREFIX("reset bloom filter");
    reset_bloom_filter(bloom_filter_tmp);
    // 3.5 再次进行 check
    for (index = 0; index < 3; index++) {
        int checkElement = allElements[index];
        if (0 == check_element_in_bloom_filter(bloom_filter_tmp, &(checkElement), sizeof(checkElement))) {
            sprintf(printBuffer, "element %d in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        } else {
            sprintf(printBuffer, "element %d not in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        }
    }
    // 3.6 逐个进行元素的插入
    LOG_WITH_PREFIX("insert element one by one");
    push_element_into_bloom_filter(bloom_filter_tmp, &first_insert_element, sizeof(first_insert_element));
    push_element_into_bloom_filter(bloom_filter_tmp, &second_insert_element, sizeof(second_insert_element));
    // 3.7 再次进行check
    for (index = 0; index < 3; index++) {
        int checkElement = allElements[index];
        if (0 == check_element_in_bloom_filter(bloom_filter_tmp, &(checkElement), sizeof(checkElement))) {
            sprintf(printBuffer, "element %d in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        } else {
            sprintf(printBuffer, "element %d not in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        }
    }
    // 3.8 进行拷贝
    LOG_WITH_PREFIX("bloom filter copy");
    struct BloomFilter *bloom_filter_copy = copy_bloom_filter(bloom_filter_tmp);
    // 3.9 再次进行 check
    for (index = 0; index < 3; index++) {
        int checkElement = allElements[index];
        if (0 == check_element_in_bloom_filter(bloom_filter_copy, &(checkElement), sizeof(checkElement))) {
            sprintf(printBuffer, "element %d in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        } else {
            sprintf(printBuffer, "element %d not in bloom filter", checkElement);
            LOG_WITH_PREFIX(printBuffer);
        }
    }
    // --------------------------------------------------------------------
    // 资源的释放
    delete_bloom_filter(bloom_filter_tmp);
    delete_bloom_filter(bloom_filter_copy);
    kfree(allElements);
    kfree(insertElements);
    LOG_WITH_EDGE("end to test bloom filter");
}