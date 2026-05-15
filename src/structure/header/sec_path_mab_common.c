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
    sec_path_mab_settings->current_packet_index = 0;
    sec_path_mab_settings->current_retrieve_index = 0;

    sec_path_mab_settings->dynamic_part = (struct SecPathMabSettingsDynamicPart*) kmalloc(sizeof(struct SecPathMabSettingsDynamicPart), GFP_KERNEL);
    sec_path_mab_settings->dynamic_part->best_path_id = 1;
    sec_path_mab_settings->dynamic_part->send_sample_packets_flag = false;
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
        if (NULL != sec_path_mab_settings->dynamic_part){
            kfree(sec_path_mab_settings->dynamic_part);
        }
        kfree(sec_path_mab_settings);
    }
}

bool get_send_sample_packets_flag(struct SecPathMabSettings *sec_path_mab_settings) {
    struct SecPathMabSettingsDynamicPart* sec_path_mab_dynamic_part;
    int send_sample_packets_flag;
    // 1. 进入临界区
    rcu_read_lock();

    // 2. 获取指针
    sec_path_mab_dynamic_part = rcu_dereference(sec_path_mab_settings->dynamic_part);

    // 3. 获取值
    if(sec_path_mab_dynamic_part){
        send_sample_packets_flag = sec_path_mab_dynamic_part->send_sample_packets_flag;
    } else {
        // 如果 dynamic_part 还没有被初始化，则返回一个默认值
        send_sample_packets_flag = false; // 或者其他适当的默认值
        printk(KERN_EMERG "get send sample packets flag failed, dynamic part is not initialized yet.\n");
    }

    rcu_read_unlock();
    return send_sample_packets_flag;
}

void set_send_sample_packets_flag(struct SecPathMabSettings *sec_path_mab_settings, bool send_sample_packets) {
    struct SecPathMabSettingsDynamicPart* new_dynamic_part = (struct SecPathMabSettingsDynamicPart*) kmalloc(sizeof(struct SecPathMabSettingsDynamicPart), GFP_KERNEL);
    if(!new_dynamic_part){
        return;
    }
    new_dynamic_part->send_sample_packets_flag = send_sample_packets;
    new_dynamic_part->best_path_id = sec_path_mab_settings->dynamic_part->best_path_id;

    // 1. 写端互斥
    spin_lock_bh(&sec_path_mab_settings->lock);

    // 2. 获取老指针
    struct SecPathMabSettingsDynamicPart* old_dynamic_part = rcu_dereference_protected(sec_path_mab_settings->dynamic_part,
            lockdep_is_held(&sec_path_mab_settings->lock));

    // 3. 原子地将新指针发布出去
    rcu_assign_pointer(sec_path_mab_settings->dynamic_part, new_dynamic_part);

    spin_unlock_bh(&sec_path_mab_settings->lock);

    // 4. 异步地释放老指针
    if(old_dynamic_part){
        kfree_rcu(old_dynamic_part, rcu);
    }

    //    5. 进行
    //    spin_lock_bh(&(sec_path_mab_settings->lock));
    //    sec_path_mab_settings->send_sample_packets_flag = send_sample_packets;
    //    spin_unlock_bh(&(sec_path_mab_settings->lock));
}


void set_best_path_id(struct SecPathMabSettings *sec_path_mab_settings, int best_path_id) {
    struct SecPathMabSettingsDynamicPart* new_dynamic_part = (struct SecPathMabSettingsDynamicPart*) kmalloc(sizeof(struct SecPathMabSettingsDynamicPart), GFP_KERNEL);
    if(!new_dynamic_part){
        return;
    }
    new_dynamic_part->send_sample_packets_flag = sec_path_mab_settings->dynamic_part->send_sample_packets_flag;
    new_dynamic_part->best_path_id = best_path_id;

    // 1. 写端互斥
    spin_lock_bh(&sec_path_mab_settings->lock);

    // 2. 获取老指针
    struct SecPathMabSettingsDynamicPart* old_dynamic_part = rcu_dereference_protected(sec_path_mab_settings->dynamic_part,
            lockdep_is_held(&sec_path_mab_settings->lock));

    // 3. 原子地将新指针发布出去
    rcu_assign_pointer(sec_path_mab_settings->dynamic_part, new_dynamic_part);

    // 4. 退出临界区
    spin_unlock_bh(&sec_path_mab_settings->lock);


    // 5. 异步地释放老指针
    if(old_dynamic_part){
        kfree_rcu(old_dynamic_part, rcu);
    }

    //    spin_lock_bh(&(sec_path_mab_settings->lock));
    //    sec_path_mab_settings->best_path_id = best_path_id;
    //    spin_unlock_bh(&(sec_path_mab_settings->lock));
}

int get_best_path_id(struct SecPathMabSettings *sec_path_mab_settings) {
    /*
    int best_path_id;
    spin_lock_bh(&(sec_path_mab_settings->lock));
    best_path_id = sec_path_mab_settings->best_path_id;
    spin_unlock_bh(&(sec_path_mab_settings->lock));
    return best_path_id;
    */
    struct SecPathMabSettingsDynamicPart* sec_path_mab_dynamic_part;
    int path_id;

    // 1. 进入临界区
    rcu_read_lock();


    // 2. 获取指针
    sec_path_mab_dynamic_part = rcu_dereference(sec_path_mab_settings->dynamic_part);

    // 3. 获取值
    if(sec_path_mab_dynamic_part){
        path_id = sec_path_mab_dynamic_part->best_path_id;
    } else {
        // 如果 dynamic_part 还没有被初始化，则返回一个默认值
        path_id = -1; // 或者其他适当的默认值
        printk(KERN_EMERG "get best path id failed, dynamic part is not initialized yet.\n");
    }

    // 4. 退出 rcu 临界区
    rcu_read_unlock();

    return path_id;
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