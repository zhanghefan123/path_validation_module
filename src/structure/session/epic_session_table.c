#include "tools/tools.h"
#include "structure/session/epic_session_table.h"
#include "structure/routing/table_common.h"



// entry 相关代码
// ---------------------------------------------------------------------------------------------------------------
// 创建 epic session 表项
struct EpicSessionTableEntry* init_este(int source,  int destination, u32 path_timestamp,
        struct EpicHopIdentifier* hop_identifiers, struct EpicHopAuthenticator* hop_authenticators, int length_of_path, struct InterfaceTableEntry* ite){
    // 1.获取 EpicHopIdentifier 的数量
    int epic_session_hops = length_of_path - 1;
    // 2. 进行 EpicSessionTableEntry 的创建
    struct EpicSessionTableEntry *este = (struct EpicSessionTableEntry*)kmalloc(sizeof(struct EpicSessionTableEntry), GFP_KERNEL);
    este->meta.source = source;
    este->meta.destination= destination;
    este->meta.ite = ite;
    este->meta.epic_session_hops = epic_session_hops;
    este->meta.path_timestamp = path_timestamp;
    // 3. 进行 hop_identifiers 和 hop_authenticators 的内存分配
    este->hop_identifiers = (struct EpicHopIdentifier *)kmalloc(sizeof(struct EpicHopIdentifier)*epic_session_hops, GFP_KERNEL);
    este->hop_authenticators = (struct EpicHopAuthenticator*)kmalloc(sizeof(struct EpicHopAuthenticator)*epic_session_hops, GFP_KERNEL);
    // 4. 进行拷贝
    memcpy((unsigned char*)este->hop_identifiers, hop_identifiers, sizeof(struct EpicHopIdentifier) * epic_session_hops);
    memcpy((unsigned char*)este->hop_authenticators, hop_authenticators, sizeof(struct EpicHopAuthenticator) * epic_session_hops);

    return este;
}

// 进行单个表项的释放 -> 整个都是由 kmalloc 进行内存分配的
void free_este(struct EpicSessionTableEntry* este){
    if(NULL != este){
        // 释放 este 内部的内存
        if (NULL != este->hop_identifiers){
            kfree(este->hop_identifiers);
        }
        if (NULL != este->hop_authenticators){
            kfree(este->hop_authenticators);
        }
        // 释放 este 的内存
        kfree(este);
    }
}

// ---------------------------------------------------------------------------------------------------------------

// session table 相关代码
// ---------------------------------------------------------------------------------------------------------------

/**
 * 基于 source destination 进行哈希的计算
 * @param source
 * @param destination
 * @return
 */
u64 calculate_hash_based_on_src_dest(int source, int destination){
    // 创建一个数组
    int source_and_dest_pair[2] = {source, destination};
    // 进行 hash 值的计算
    u32 hash_value = jhash(source_and_dest_pair, sizeof(int) * 2, 1234);
    // 返回计算的haxi
    return hash_value;
}

/**
 * 初始化基于哈希的EPIC会话表
 * @param bucket_count 桶的数量
 * @return
 */
struct HashBasedEpicSessionTable *init_hbest(int bucket_count) {
    int index;
    // 链地址发的左侧竖直的列表
    struct hlist_head *head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * bucket_count, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
    }
    // 初始化表头
    for (index = 0; index < bucket_count; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    // 创建 hash based session table
    struct HashBasedEpicSessionTable *hbest = (struct HashBasedEpicSessionTable *) kmalloc(sizeof(struct HashBasedEpicSessionTable),
                                                                                  GFP_KERNEL);
    hbest->bucket_count = bucket_count;
    hbest->bucket_array = head_pointer_list;

    // 初始化自旋锁
    spin_lock_init(&(hbest->lock));
    return hbest;
}

/**
 * 进行基于哈希的会话表的释放
 * @param hbest 基于哈希的会话表
 * @return
 */
int free_hbest(struct HashBasedEpicSessionTable *hbest) {
    // 这里首先判断要进行 free 的 hbrt 是否为 NULL
    if (NULL != hbest) {
        int index;
        struct hlist_head *hash_bucket = NULL;
        struct EpicSessionTableEntry *current_entry = NULL;
        struct hlist_node *next;
        printk(KERN_EMERG "hash bucket count: %d \n", hbest->bucket_count);
        for (index = 0; index < hbest->bucket_count; index++) {
            hash_bucket = &(hbest->bucket_array[index]);
            // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
            if (NULL == hash_bucket) {
                LOG_WITH_PREFIX("hash bucket is null");
                return -1;
            }
            hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
                if (NULL != current_entry) {
                    hlist_del(&current_entry->pointer);
                    free_este(current_entry);
                }
            }
        }
        // 清空 head_pointer_list 引入的 memory 开销
        if (NULL != hbest->bucket_array) {
            kfree(hbest->bucket_array);
            hbest->bucket_array = NULL;
        }
        // 释放 hbest
        kfree(hbest);
        LOG_WITH_PREFIX("delete hash based epic session table successfully!");
    } else {
        LOG_WITH_PREFIX("hash based epic session table is NULL");
    }
    return 0;
}

/**
 * 根据 src dest 计算出哈希值之后找到对应的 bucket
 * @param hbest
 * @param source
 * @param destination
 * @return
 */
struct hlist_head *get_bucket_in_hbest(struct HashBasedEpicSessionTable *hbest, int source, int destination) {
    // 获取 hash_truncate
    u64 hash_truncate = calculate_hash_based_on_src_dest(source, destination);
    // 找到对应的桶的索引
    u64 index_of_bucket;
    index_of_bucket = hash_truncate % hbest->bucket_count;
    // 返回对应的桶
    return &hbest->bucket_array[index_of_bucket];
}

/**
 * 判断两个表项是否相等
 * @param entry
 * @param source
 * @param destination
 * @param length_of_path
 * @return
 */
int epic_session_table_entry_equal_judgement(struct EpicSessionTableEntry *entry, int source, int destination){
    if(NULL == entry){
        return 1;
    }
    // 如果两个表项的三者都相同
    if((entry->meta.source == source) && (entry->meta.destination== destination)) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * 添加表项到表之中
 * @param hbest
 * @param este
 * @return
 */
int add_entry_to_hbest(struct HashBasedEpicSessionTable *hbest, struct EpicSessionTableEntry* este){
    struct hlist_head *hash_bucket = NULL;
    struct EpicSessionTableEntry *current_este = NULL;
    struct hlist_node *next = NULL;
    // 获取锁（自旋锁或互斥锁，取决于上下文）
    spin_lock(&hbest->lock);  // 或 mutex_lock
    // 首先找到对应的应该存放的 bucket
    hash_bucket = get_bucket_in_hbest(hbest, este->meta.source, este->meta.destination);
    if (NULL == hash_bucket) {
        // 找不到 hash_bucket
        LOG_WITH_PREFIX("cannot find hash bucket");
        free_este(este);
        return CANNOT_FIND_BUCKET;
    }
    // 检查是否出现了相同的会话表项
    hlist_for_each_entry_safe(current_este, next, hash_bucket, pointer) {
        if (0 == epic_session_table_entry_equal_judgement(current_este,
                                                          este->meta.source,
                                                          este->meta.destination)) {
            LOG_WITH_PREFIX("already exists session entry");
            free_este(este);
            spin_unlock(&hbest->lock);
            return ALREADY_EXISTS;
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&este->pointer);
    hlist_add_head(&este->pointer, hash_bucket);
    spin_unlock(&hbest->lock);
    return ADD_SUCCESS;
}

/**
 * 在表之中进行表项的查找
 * @param hbest
 * @param source
 * @param destination
 * @param length_of_path
 * @return
 */
struct EpicSessionTableEntry* find_este_in_hbest(struct HashBasedEpicSessionTable* hbest, int source, int destination){
    struct hlist_head *hash_bucket = NULL;
    struct EpicSessionTableEntry *current_entry = NULL;
    struct hlist_node *next;
    hash_bucket = get_bucket_in_hbest(hbest, source, destination);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == epic_session_table_entry_equal_judgement(current_entry, source, destination)) {
            return current_entry;
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------------------------------------------