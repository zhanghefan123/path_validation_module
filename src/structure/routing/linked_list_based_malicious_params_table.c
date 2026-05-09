#include <linux/list.h>
#include "tools/tools.h"
#include "structure/routing/linked_list_based_malicious_params_table.h"

struct LinkedListBasedMaliciousParamsTable *init_llbpmt(void) {
    struct LinkedListBasedMaliciousParamsTable *llbpmt = (struct LinkedListBasedMaliciousParamsTable *) kmalloc(
            sizeof(struct LinkedListBasedMaliciousParamsTable), GFP_KERNEL);
    INIT_LIST_HEAD(&(llbpmt->corrupt_ratio_entry_list));
    INIT_LIST_HEAD(&(llbpmt->corrupt_special_packet_ratio_entry_list));
    return llbpmt;
}

int free_llbpmt(struct LinkedListBasedMaliciousParamsTable *llbpmt) {
    // 这里首先判断要进行 free 的 hbrt 是否为 NULL
    if (NULL != llbpmt) {
        // 进行 corrupt_ratio_entry_list 链表的遍历删除
        struct ScheduledCorruptRatio* scheduled_corrupt_ratio_entry, *scheduled_corrupt_ratio_tmp;
        list_for_each_entry_safe(scheduled_corrupt_ratio_entry, scheduled_corrupt_ratio_tmp, &(llbpmt->corrupt_ratio_entry_list), list){
            if(NULL != scheduled_corrupt_ratio_entry) {
                list_del(&(scheduled_corrupt_ratio_entry->list));
                kfree(scheduled_corrupt_ratio_entry);
            }
        }
        // 进行 corrupt_special_packet_ratio_entry_list 链表的遍历删除
        struct ScheduledCorruptSpecialPacketRatio* scheduled_corrupt_special_packet_ratio, *scheduled_corrupt_special_packet_ratio_tmp;
        list_for_each_entry_safe(scheduled_corrupt_special_packet_ratio, scheduled_corrupt_special_packet_ratio_tmp, &(llbpmt->corrupt_special_packet_ratio_entry_list), list){
            if(NULL != scheduled_corrupt_special_packet_ratio){
                list_del(&(scheduled_corrupt_special_packet_ratio->list));
                kfree(scheduled_corrupt_special_packet_ratio);
            }
        }
        // 进行本身的删除
        kfree(llbpmt);
    }
    return 0;
}

struct ScheduledCorruptRatio *init_scheduled_corrupt_ratio(int employ_epoch_or_timestamp, int corrupt_ratio_start,
                                                           int corrupt_ratio_end) {
    struct ScheduledCorruptRatio *malicious_params_entry = (struct ScheduledCorruptRatio *) kmalloc(
            sizeof(struct ScheduledCorruptRatio), GFP_KERNEL);
    malicious_params_entry->employ_epoch_or_timestamp = employ_epoch_or_timestamp;
    malicious_params_entry->corrupt_ratio_start = corrupt_ratio_start;
    malicious_params_entry->corrupt_ratio_end = corrupt_ratio_end;
    INIT_LIST_HEAD(&(malicious_params_entry->list));
    return malicious_params_entry;
}

struct ScheduledCorruptSpecialPacketRatio *init_scheduled_corrupt_special_packet_ratio(int employ_epoch_id, int corrupt_ratio_start,
                                                          int corrupt_ratio_end) {
    struct ScheduledCorruptSpecialPacketRatio *malicious_params_entry = (struct ScheduledCorruptSpecialPacketRatio *) kmalloc(
            sizeof(struct ScheduledCorruptSpecialPacketRatio), GFP_KERNEL);
    malicious_params_entry->employ_epoch_or_timestamp = employ_epoch_id;
    malicious_params_entry->corrupt_special_packet_ratio_start = corrupt_ratio_start;
    malicious_params_entry->corrupt_special_packet_ratio_end = corrupt_ratio_end;
    INIT_LIST_HEAD(&(malicious_params_entry->list));
    return malicious_params_entry;
}


int add_corrupt_ratio_entry_to_llbpmt(struct LinkedListBasedMaliciousParamsTable *llbpmt,
                                      struct ScheduledCorruptRatio *scheduled_corrupt_ratio){
    if (NULL == scheduled_corrupt_ratio || NULL == llbpmt) {
        LOG_WITH_PREFIX("scheduled_corrupt_ratio or hbpmt is NULL");
        return -1;
    }
    list_add_tail(&(scheduled_corrupt_ratio->list), &(llbpmt->corrupt_ratio_entry_list));
    return 0;
}

int add_corrupt_special_packet_ratio_entry_to_llbpmt(struct LinkedListBasedMaliciousParamsTable *llbpmt,
                                                     struct ScheduledCorruptSpecialPacketRatio *scheduled_corrupt_special_packet_ratio){
    if (NULL == scheduled_corrupt_special_packet_ratio || NULL == llbpmt) {
        LOG_WITH_PREFIX("scheduled_corrupt_special_packet_ratio or hbpmt is NULL");
        return -1;
    }
    list_add_tail(&(scheduled_corrupt_special_packet_ratio->list), &(llbpmt->corrupt_special_packet_ratio_entry_list));
    return 0;
}