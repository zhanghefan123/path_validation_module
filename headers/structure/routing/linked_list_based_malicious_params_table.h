//
// Created by zhf on 2026/4/14.
//

#ifndef PATH_VALIDATION_MODULE_LINKED_LIST_BASED_MALICIOUS_PARAMS_TABLE_H
#define PATH_VALIDATION_MODULE_LINKED_LIST_BASED_MALICIOUS_PARAMS_TABLE_H

struct LinkedListBasedMaliciousParamsTable {
    struct list_head corrupt_ratio_entry_list; // 链表节点
    struct list_head corrupt_special_packet_ratio_entry_list; // 链表节点
};

struct ScheduledCorruptRatio {
    int employ_epoch_id;
    int corrupt_ratio_start;
    int corrupt_ratio_end;
    struct list_head list;
};

struct ScheduledCorruptSpecialPacketRatio {
    int employ_epoch_id;
    int corrupt_special_packet_ratio_start;
    int corrupt_special_packet_ratio_end;
    struct list_head list; // 链表节点
};

struct LinkedListBasedMaliciousParamsTable *init_llbpmt(void);

int free_llbpmt(struct LinkedListBasedMaliciousParamsTable *llbpmt);

struct ScheduledCorruptRatio *init_scheduled_corrupt_ratio(int employ_epoch_id, int corrupt_ratio_start,
                                                           int corrupt_ratio_end);

struct ScheduledCorruptSpecialPacketRatio *init_scheduled_corrupt_special_packet_ratio(int employ_epoch_id,
                                                                                       int corrupt_special_ratio_start,
                                                                                       int corrupt_special_ratio_end);

int add_corrupt_ratio_entry_to_llbpmt(struct LinkedListBasedMaliciousParamsTable *llbpmt,
                                      struct ScheduledCorruptRatio *malicious_params_entry);

int add_corrupt_special_packet_ratio_entry_to_llbpmt(struct LinkedListBasedMaliciousParamsTable *llbpmt,
                                                     struct ScheduledCorruptSpecialPacketRatio *malicious_params_entry);

#endif //PATH_VALIDATION_MODULE_LINKED_LIST_BASED_MALICIOUS_PARAMS_TABLE_H
