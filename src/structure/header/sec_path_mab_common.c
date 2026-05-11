#include "structure/header/sec_path_mab_common.h"
#include "structure/routing/sec_path_mab_route.h"


// 进行 vector 定义
DEFINE_XARRAY(per_packet_info_array);
DEFINE_XARRAY(example_array);

struct SecPathMabSettings *init_sec_path_mab_settings(void) {
    struct SecPathMabSettings *sec_path_mab_settings = (struct SecPathMabSettings *) (kmalloc(
            sizeof(struct SecPathMabSettings), GFP_KERNEL));
    sec_path_mab_settings->malicious_params = init_malicious_params();
    sec_path_mab_settings->current_retrieve_epoch = 1;
    sec_path_mab_settings->current_epoch = 0;
    sec_path_mab_settings->current_packet_identifier = 1;
    sec_path_mab_settings->best_path_id = 1;
    sec_path_mab_settings->current_packet_index = 0;
    sec_path_mab_settings->current_retrieve_index = 0;
    spin_lock_init(&(sec_path_mab_settings->lock));
    return sec_path_mab_settings;
}

void free_sec_path_mab_settings(struct SecPathMabSettings *sec_path_mab_settings) {
    if (NULL != sec_path_mab_settings) {
        if (NULL != sec_path_mab_settings->selected_route) {
            free_sec_path_mab_route(sec_path_mab_settings->selected_route);
        }
        if (NULL != sec_path_mab_settings->malicious_params) {
            free_malicious_params(sec_path_mab_settings->malicious_params);
        }
        kfree(sec_path_mab_settings);
    }
}

bool get_send_sample_packets(struct SecPathMabSettings *sec_path_mab_settings) {
    bool result;
    spin_lock_bh(&(sec_path_mab_settings->lock));
    result = sec_path_mab_settings->send_sample_packets;
    spin_unlock_bh(&(sec_path_mab_settings->lock));
    return result;
}

void set_send_sample_packets(struct SecPathMabSettings *sec_path_mab_settings, bool send_sample_packets) {
    spin_lock_bh(&(sec_path_mab_settings->lock));
    sec_path_mab_settings->send_sample_packets = send_sample_packets;
    spin_unlock_bh(&(sec_path_mab_settings->lock));
}


void set_best_path_id(struct SecPathMabSettings *sec_path_mab_settings, int best_path_id) {
    spin_lock_bh(&(sec_path_mab_settings->lock));
    sec_path_mab_settings->best_path_id = best_path_id;
    spin_unlock_bh(&(sec_path_mab_settings->lock));
}

void test_xarray(void) {
    int index;
    for (index = 0; index < 10; index++) {
        int *value = (int *) kmalloc(sizeof(int), GFP_KERNEL);
        *value = index * 10;
        xa_store(&example_array, index, value, GFP_KERNEL);
    }
    for (index = 0; index < 10; index++) {
        int *value = xa_load(&example_array, index);
        printk(KERN_EMERG "retrieved value: %d\n", *value);
        value = xa_erase(&example_array, index);
        if (NULL != value) {
            kfree(value);
        }
    }
}

void free_xarray(void) {
    // 进行 xarray 的释放
    xa_destroy(&per_packet_info_array);
    xa_destroy(&example_array);
}