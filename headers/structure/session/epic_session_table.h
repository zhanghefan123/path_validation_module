//
// Created by zhf on 2025/12/1.
//

#ifndef PATH_VALIDATION_MODULE_EPIC_SESSION_TABLE_H
#define PATH_VALIDATION_MODULE_EPIC_SESSION_TABLE_H
#include "structure/header/epic_header.h"
#include "structure/header/epic_session_header.h"
#include "structure/interface/interface_table.h"



// entry 相关代码
// ---------------------------------------------------------------------------------------------------------------

struct EpicSessionTableEntryMeta {
    u64 source;
    u64 destination;
    u32 epic_session_hops;
    u64 path_timestamp;
    struct InterfaceTableEntry* ite; // 出接口
};

struct EpicSessionTableEntry {
    struct EpicSessionTableEntryMeta meta;
    struct EpicHopIdentifier* hop_identifiers; // i.e., Hi
    struct EpicHopAuthenticator* hop_authenticators; // i.e., sigma_i
    struct hlist_node pointer; // 指向的是下一个节点
};

struct EpicSessionTableEntry* init_este(int source, int destination, u32 path_timestamp,
        struct EpicHopIdentifier* hop_identifiers, struct EpicHopAuthenticator* hop_authenticators, int length_of_path,
        struct InterfaceTableEntry* ite);

void free_este(struct EpicSessionTableEntry *este);
// ---------------------------------------------------------------------------------------------------------------

// session table 相关代码
// ---------------------------------------------------------------------------------------------------------------
struct HashBasedEpicSessionTable {
    // 使用的桶的数量
    int bucket_count;
    // 哈希表
    struct hlist_head *bucket_array;
    // 自旋锁
    spinlock_t lock;
};

u64 calculate_hash_based_on_src_dest(int source, int destination);

struct HashBasedEpicSessionTable *init_hbest(int bucket_count);

int free_hbest(struct HashBasedEpicSessionTable *hbst);

struct hlist_head *get_bucket_in_hbest(struct HashBasedEpicSessionTable *hbst, int source, int destination);

int epic_session_table_entry_equal_judgement(struct EpicSessionTableEntry *entry, int source, int destination);

int add_entry_to_hbest(struct HashBasedEpicSessionTable *hbst, struct EpicSessionTableEntry* este);

struct EpicSessionTableEntry *find_este_in_hbest(struct HashBasedEpicSessionTable *hbst, int source, int destination);
// ---------------------------------------------------------------------------------------------------------------
#endif //PATH_VALIDATION_MODULE_EPIC_SESSION_TABLE_H
