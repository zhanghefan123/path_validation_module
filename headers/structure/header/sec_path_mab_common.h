#ifndef PATH_VALIDATION_MODULE_SEC_PATH_HEADER_H
#define PATH_VALIDATION_MODULE_SEC_PATH_HEADER_H
#include "structure/routing/sec_path_mab_route.h"
#include "structure/interface/interface_table.h"
#include "structure/malicious/malicious_params.h"
#include <net/ip.h>
struct SecPathMabHopIdentifier {
    __u8 link_id;
    __u8 incoming_link_id;
};

struct SecPathMabPathPart {
    struct SecPathMabHopIdentifier hop_identifiers[0]; // hop identifier list
};

struct SecPathMabSettings {
    int current_epoch; // 当前的 epoch
    int current_retrieve_epoch; // 当前需要还没进行获取的 epoch
    struct SecPathMabRoute* selected_route; // 当前由用户空间所选择的路径
    struct MaliciousParams* malicious_params; // 恶意参数
    int current_packet_identifier; // 当前的包计数器
    int sec_path_mab_type;    // sec_path_mab 类型
    int min_ack_for_rtt_estimation; // rtt estimation
    bool send_sample_packets; // 是否当前进行采样包的发送
    spinlock_t lock;
};

struct SecPathMabSettings* init_sec_path_mab_settings(void);

void free_sec_path_mab_settings(struct SecPathMabSettings* sec_path_mab_settings);

bool get_send_sample_packets(struct SecPathMabSettings* sec_path_mab_settings);

void set_send_sample_packets(struct SecPathMabSettings* sec_path_mab_settings, bool send_sample_packets);

#endif