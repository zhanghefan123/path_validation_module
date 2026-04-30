//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_RCV_H
#define LOADABLE_KERNEL_MODULE_IP_RCV_H
#include <net/ip.h>
#include "api/ftrace_hook_api.h"
#include "structure/path_validation_structure.h"
#include "structure/header/lir_header.h"

// 前面还有
// #define NET_RX_SUCCESS		0	/* keep 'em coming, baby */
// #define NET_RX_DROP		1	/* packet dropped */
#define NET_RX_NOTHING 2
#define NET_RX_FORWARD_FAILED 3


struct AncestorResult {
    int ancestor_count;
    int* ancestors;
};

struct Result{
    struct list_head* validation_segment_list; // intersaction (要进行 opv 校验的)
    struct list_head* decision_segment_list; // not intersaction (全部的本地存储的)
    unsigned char** validation_pointer_array;
    unsigned char** decision_pointer_array;
    int validation_segment_count;
    int decision_segment_count;
};

struct ProofVerificationResult{
    bool verification_result;
    struct AtlasSegment* selected_atlas_segment;
};

void free_result(struct Result* result);

bool resolve_ip_rcv_inner_functions_address(void);
int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
                        struct net_device *orig_dev, u64 start);
int self_defined_ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb, u64 start);
int lir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int icing_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int opt_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int sec_path_mab_rcv(struct sk_buff* skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
int sec_path_mab_ack_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int fast_selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev,  u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int multicast_selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int multicast_opt_rcv(struct sk_buff* skb, struct net_device* dev, struct net_device* orig_dev);
int session_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int epic_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int atlas_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed,  u64* find_segments_time);
void traverse_and_set_to_delete(unsigned char* current_pointer);
//bool judge_if_the_possible_parent(int segment_id, const int* all_parent_ids, int count);
int epic_session_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int multicast_session_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int multipath_fast_selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev,
        u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed, u64* find_segments_time_elapsed);

struct sk_buff* lir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* icing_rcv_validate(struct sk_buff*skb, struct net* net);
struct sk_buff* opt_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* sec_path_mab_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* sec_path_mab_ack_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* selir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* multicast_selir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* multicast_opt_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* session_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* epic_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* epic_session_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* multicast_session_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* multipath_fast_selir_rcv_validate(struct sk_buff* skb, struct net*net);


//int opt_forward_session_establish_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int atlas_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev,
        u64* intermediate_verification_time_elapsed, u64* destination_verification_time, u64* find_segments_time);
int epic_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int opt_forward_data_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
void sec_path_mab_normal_router_process_data_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev);
int sec_path_mab_pv_router_process_data_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev);
int sec_path_mab_ack_pv_router_process_ack_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev);
void sec_path_mab_ack_normal_router_process_ack_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev);
int lir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int icing_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* encryption_time_elapsed);
int fast_selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev,u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed);
int multicast_selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int multicast_opt_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
    int forward_session_setup_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns);
int forward_multicast_session_setup_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev);
int forward_epic_session_setup_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns,  struct net_device* orig_dev);
void print_lir_forwarding_time_consumption(int current_hop, struct PathValidationStructure* pvs, u64 start_time);
int multipath_fast_selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev,
                                         u64* intermediate_verification_time_elapsed, u64* destination_verification_time, u64* find_segments_time);


void add_ip_rcv_to_hook(void);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif //LOADABLE_KERNEL_MODULE_IP_RCV_H
