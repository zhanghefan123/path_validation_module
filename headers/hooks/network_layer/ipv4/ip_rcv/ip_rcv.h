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

bool resolve_ip_rcv_inner_functions_address(void);
int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
                        struct net_device *orig_dev, u64 start);
int self_defined_ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb, u64 start);
int lir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int icing_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
int opt_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int fast_selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int multicast_selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int session_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int multicast_session_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);


struct sk_buff* lir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* icing_rcv_validate(struct sk_buff*skb, struct net* net);
struct sk_buff* opt_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* selir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* multicast_selir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* session_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* multicast_session_rcv_validate(struct sk_buff* skb, struct net* net);


//int opt_forward_session_establish_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int opt_forward_data_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* encryption_time_elapsed);
int lir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int icing_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* encryption_time_elapsed);
int selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* encryption_time_elapsed);
int fast_selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int multicast_selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, int* current_hop);
int forward_session_setup_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns);
int forward_multicast_session_setup_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns);

void print_lir_forwarding_time_consumption(int current_hop, struct PathValidationStructure* pvs, u64 start_time);

void add_ip_rcv_to_hook(void);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif //LOADABLE_KERNEL_MODULE_IP_RCV_H
