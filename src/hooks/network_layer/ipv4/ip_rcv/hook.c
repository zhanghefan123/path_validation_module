#include "tools/tools.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/namespace/namespace.h"
#include <net/inet_ecn.h>

asmlinkage int(*orig_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

asmlinkage int hook_ip_rcv(struct sk_buff *skb,
                           struct net_device *dev,
                           struct packet_type *pt,
                           struct net_device *orig_dev) {
    int version_number = ip_hdr(skb)->version;
    if (IP_VERSION_NUMBER == version_number){
        int result = self_defined_ip_rcv(skb, dev, pt, orig_dev, ktime_get_real_ns());
        return result;
    } else {
        if (LIR_VERSION_NUMBER == version_number) {
            return lir_rcv(skb, dev, pt, orig_dev);
        } else if (ICING_VERSION_NUMBER == version_number) {
            u64 intermediate_verification_time_elapsed = 0;
            u64 destination_verification_time_elapsed = 0;
//            u64 start_time = ktime_get_real_ns();
            int result = icing_rcv(skb, dev, pt, orig_dev, &intermediate_verification_time_elapsed, &destination_verification_time_elapsed);
//            if (0 != intermediate_verification_time_elapsed) {
//                printk(KERN_EMERG "icing rcv time: %llu ns | icing intermediate verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       intermediate_verification_time_elapsed);
//            } else {
//                printk(KERN_EMERG "icing rcv time: %llu ns | icing destination verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       destination_verification_time_elapsed);
//            }
            return result;
        } else if (SESSION_SETUP_VERSION_NUMBER == version_number){
            return session_rcv(skb, dev, pt, orig_dev);
        } else if (MULTICAST_SESSION_SETUP_VERSION_NUMBER == version_number){
            return multicast_session_rcv(skb, dev, pt, orig_dev);
        } else if (OPT_VERSION_NUMBER == version_number) {
            u64 intermediate_verification_time_elapsed = 0;
            u64 destination_verification_time_elapsed = 0;
//            u64 start_time = ktime_get_real_ns();
            int result = opt_rcv(skb, dev, pt, orig_dev, &intermediate_verification_time_elapsed, &destination_verification_time_elapsed);
//            if (0 != intermediate_verification_time_elapsed) {
//                printk(KERN_EMERG "opt rcv time: %llu ns | opt intermediate verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       intermediate_verification_time_elapsed);
//            } else {
//                printk(KERN_EMERG "opt rcv time: %llu ns | opt destination verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       destination_verification_time_elapsed);
//            }
            return result;
        } else if (SEC_PATH_MAB_VERSION_NUMBER == version_number){
            return sec_path_mab_rcv(skb, dev, pt, orig_dev);
//            kfree_skb(skb);
//            return 0;
        } else if (SEC_PATH_MAB_ACK_VERSION_NUMBER == version_number) {
            return sec_path_mab_ack_rcv(skb, dev, pt, orig_dev);
        } else if(SELIR_VERSION_NUMBER == version_number) {
            return selir_rcv(skb, dev, pt, orig_dev);
        } else if(FAST_SELIR_VERSION_NUMBER == version_number) {
            u64 intermediate_verification_time_elapsed = 0;
            u64 destination_verification_time_elapsed = 0;
//            u64 start_time = ktime_get_real_ns();
            int result =  fast_selir_rcv(skb, dev, pt, orig_dev, &intermediate_verification_time_elapsed, &destination_verification_time_elapsed);
//            if (0 != intermediate_verification_time_elapsed) {
//                printk(KERN_EMERG "fast selir rcv time: %llu ns | fast selir intermediate verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       intermediate_verification_time_elapsed);
//            } else {
//                printk(KERN_EMERG "fast selir rcv time: %llu ns | fast selir destination verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       destination_verification_time_elapsed);
//            }
            return result;
        } else if(MULTICAST_SELIR_VERSION_NUMBER == version_number){
//            struct net* net = dev_net(orig_dev);
//            struct PathValidationStructure* pvs = get_pvs_from_ns(net);
//            u64 verification_start_time = ktime_get_real_ns();
            int result = multicast_selir_rcv(skb, dev, pt, orig_dev);
//            printk(KERN_EMERG "multicast lip %d rcv time: %llu ns\n", pvs->node_id, ktime_get_real_ns() - verification_start_time);
            return result;
        } else if(MULTICAST_OPT_VERSION_NUMBER == version_number){
//            struct net *net = dev_net(orig_dev);
//            struct PathValidationStructure *pvs = get_pvs_from_ns(net);
//            u64 verification_start_time = ktime_get_real_ns();
            int result = multicast_opt_rcv(skb, dev, orig_dev);
//            printk(KERN_EMERG "multicast opt %d rcv time: %llu ns\n", pvs->node_id, ktime_get_real_ns() - verification_start_time);
            return result;
        } else if(EPIC_SESSION_VERSION_NUMBER == version_number){
            return epic_session_rcv(skb, dev, pt, orig_dev);
        } else if(EPIC_VERSION_NUMBER == version_number){
            u64 intermediate_verification_time_elapsed = 0;
            u64 destination_verification_time_elapsed = 0;
//            u64 start_time = ktime_get_real_ns();
            int result =  epic_rcv(skb, dev, pt, orig_dev, &intermediate_verification_time_elapsed, &destination_verification_time_elapsed);
//            if (0 != intermediate_verification_time_elapsed) {
//                printk(KERN_EMERG "epic rcv time: %llu ns | epic intermediate verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       intermediate_verification_time_elapsed);
//            } else {
//                printk(KERN_EMERG "epic rcv time: %llu ns | epic destination verification time: %llu ns\n", ktime_get_real_ns() - start_time,
//                       destination_verification_time_elapsed);
//            }
            return result;
        } else if(ATLAS_VERSION_NUMBER == version_number){
            u64 intermediate_verification_time_elapsed = 0;
            u64 destination_verification_time_elapsed = 0;
            u64 find_segments_time_elapsed = 0;
            int result = atlas_rcv(skb,dev,pt,orig_dev, &intermediate_verification_time_elapsed, &destination_verification_time_elapsed, &find_segments_time_elapsed);
//            if (0 != intermediate_verification_time_elapsed){
//                printk(KERN_EMERG "atlas intermediate verification time: %llu ns | find segments time: %llu ns | enc time: %llu ns\n",
//                       intermediate_verification_time_elapsed, find_segments_time_elapsed, intermediate_verification_time_elapsed - find_segments_time_elapsed);
//            } else {
//                printk(KERN_EMERG "atlas destination verificaition time: %llu ns | find segments time: %llu ns | enc time: %llu ns\n",
//                       destination_verification_time_elapsed, find_segments_time_elapsed, destination_verification_time_elapsed - find_segments_time_elapsed);
//            }
            return result;
//             printk(KERN_EMERG "receive atlas data packet\n");
//            return atlas_rcv(skb, dev, pt, orig_dev);
//            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
//            return -EINVAL;
        } else if(MULTIPATH_SELIR_VERSION_NUMBER == version_number) {
            u64 intermediate_verification_time_elapsed = 0;
            u64 destination_verification_time_elapsed = 0;
            u64 find_segments_time_elapsed = 0;
            int result =  multipath_fast_selir_rcv(skb, dev, pt , orig_dev, &intermediate_verification_time_elapsed, &destination_verification_time_elapsed, &find_segments_time_elapsed);
//            if (0 != intermediate_verification_time_elapsed) {
//                printk(KERN_EMERG "multipath selir intermediate verification time: %llu ns | find segments time: %llu ns\n",
//                       intermediate_verification_time_elapsed, find_segments_time_elapsed);
//            } else {
//                printk(KERN_EMERG "multipath selir destination verification time: %llu ns | find segments time: %llu ns\n",
//                       destination_verification_time_elapsed, find_segments_time_elapsed);
//            }
            return result;
        } else {
            LOG_WITH_PREFIX("unknown packet type");
            return -EINVAL;
        }
    }
}

void add_ip_rcv_to_hook(void){
    hooks[number_of_hook].name = "ip_rcv";
    hooks[number_of_hook].function = hook_ip_rcv;
    hooks[number_of_hook].original = &orig_ip_rcv;
    number_of_hook += 1;
}