#include "structure/header/sec_path_mab_common.h"
#include "structure/routing/sec_path_mab_route.h"

struct SecPathMabSettings* init_sec_path_mab_settings(void) {
    struct SecPathMabSettings* sec_path_mab_settings =  (struct SecPathMabSettings*)(kmalloc(sizeof(struct SecPathMabSettings), GFP_KERNEL));
    sec_path_mab_settings->malicious_params = init_malicious_params();
    sec_path_mab_settings->current_retrieve_epoch = 1;
    sec_path_mab_settings->current_epoch = 0;
    sec_path_mab_settings->current_packet_identifier = 1;
    spin_lock_init(&(sec_path_mab_settings->lock));
    return sec_path_mab_settings;
}

void free_sec_path_mab_settings(struct SecPathMabSettings* sec_path_mab_settings){
    if(NULL != sec_path_mab_settings){
        if(NULL != sec_path_mab_settings->selected_route){
            free_sec_path_mab_route(sec_path_mab_settings->selected_route);
        }
        if(NULL != sec_path_mab_settings->malicious_params){
            free_malicious_params(sec_path_mab_settings->malicious_params);
        }
        kfree(sec_path_mab_settings);
    }
}

bool get_send_sample_packets(struct SecPathMabSettings* sec_path_mab_settings){
    bool result;
    spin_lock_bh(&(sec_path_mab_settings->lock));
    result= sec_path_mab_settings->send_sample_packets;
    spin_unlock_bh(&(sec_path_mab_settings->lock));
    return result;
}

void set_send_sample_packets(struct SecPathMabSettings* sec_path_mab_settings, bool send_sample_packets){
    spin_lock_bh(&(sec_path_mab_settings->lock));
    sec_path_mab_settings->send_sample_packets = send_sample_packets;
    spin_unlock_bh(&(sec_path_mab_settings->lock));
}
