#include <net/inet_ecn.h>
#include "tools/tools.h"
#include "types/router_types.h"
#include "structure/namespace/namespace.h"
#include "structure/header/sec_path_mab_ack_header.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

/**
 * 目的节点收到了 ack 的操作, 首先查找对应的 epoch 之中的 ack_map 是否存在相应的表项, 然后查找 cnt_map 之中的表项并进行 ++ 的操作
 * @param skb
 * @param pvs
 */
static void desitination_handle_ack(struct sk_buff* skb, struct PathValidationStructure* pvs){
    // rtt
    u64 rtt_us = 0;
    // ack index
    int sample_router_index = 0;
    // get current time stamp
    u64 current_timestamp = ktime_get_us();
    // get the header
    struct SecPathMabAckHeader* sec_path_mab_ack_header = sec_path_mab_ack_hdr(skb);
    // get the ack epoch
    int epoch = sec_path_mab_ack_header->epoch;
    // get the hbace
    struct HashBasedAckCacheTableForEachEpoch* hbace = pvs->hbace;
    // get the ack content
    unsigned char* content = (unsigned char*)get_sec_path_mab_ack_validation_part(sec_path_mab_ack_header);
    // find the hbase in hbace with epoch
    struct HashBasedAckCacheTableForSingleEpoch* hbase = find_hbase_in_hbace(hbace, epoch);
    if (NULL == hbase){
        LOG_WITH_PREFIX("cannot find hbase in hbace\n");
        return;
    }
    // find ack cache entry in the hbase
    struct AckCacheEntry* ack_cache_entry = find_cache_entry_in_hbase(hbase, content);
    if(NULL == ack_cache_entry){
        // printk(KERN_EMERG "cannot find ack cache entry with epoch = %d, identifier = %d in hbase\n", epoch, sec_path_mab_ack_header->identifier);
        print_memory_in_hex(content, ACK_AUTHENTICATION_LENGTH);
        return;
    } else {
        // printk(KERN_EMERG "find ack cache entry with epoch = %d, identifier = %d, sample_router index %d in hbase\n", epoch, sec_path_mab_ack_header->identifier, ack_cache_entry->sample_router_index);
        // print_memory_in_hex(content, ACK_AUTHENTICATION_LENGTH);
        rtt_us = (current_timestamp - ack_cache_entry->current_timestamp);
        sample_router_index = ack_cache_entry->sample_router_index;
        // 进行锁的添加
        spin_lock_bh(&(hbase->lock));
        free_ack_cache_entry_with_pointer(ack_cache_entry);
        // 进行锁的释放
        spin_unlock_bh(&(hbase->lock));
    }
    // find sfse in hbale with epoch
    struct StatisticsForSingleEpoch* sfse = find_sfse_in_hbale(pvs->hbale, epoch);
    if(NULL == sfse){
        LOG_WITH_PREFIX("cannot find sfse in hbale\n");
        return;
    } else {
        update_sfse_with_new_ack(sfse, sample_router_index, rtt_us);
    }
}

/**
 * 如果收到了 ack 的处理流程
 * @param skb
 * @param dev
 * @param pt
 * @param orig_dev
 * @return
 */
int sec_path_mab_ack_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev){
    struct net *current_ns = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 1. 初始化变量
    int process_result;
    // 2. 进行初级的校验
    skb = sec_path_mab_ack_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    // 3. 进行不同的数据包的处理
    if(pvs->router_type == ROUTER_TYPE_NORMAL){ // 3.1 进行一般的路由器的处理
        // printk(KERN_EMERG "normal router %d receives ack packet\n", pvs->node_id);
        // 3.1.1 进行数据包的处理
        sec_path_mab_ack_normal_router_process_ack_packets(skb, pvs, current_ns, orig_dev);
        // 3.1.2 直接返回
        return NET_RX_DROP;
    } else if (pvs->router_type == ROUTER_TYPE_PATH_VALIDATION){ // 3.2 进行路径校验的路由器的处理
        // printk(KERN_EMERG "path validation router %d receives ack packet\n", pvs->node_id);
        process_result = sec_path_mab_ack_pv_router_process_ack_packets(skb, pvs, current_ns, orig_dev);
        if (NET_RX_SUCCESS == process_result) {
            // 源节点收到 ack 之后进行处理
            desitination_handle_ack(skb, pvs);
            // 最终需要进行丢包
            if(NULL != skb){
                kfree_skb(skb);
            }
        }
        return NET_RX_DROP;
    } else {
        printk(KERN_EMERG "invalid router type: %d\n", pvs->router_type);
        kfree_skb(skb);
        return NET_RX_DROP;
    }
}



struct sk_buff* sec_path_mab_ack_rcv_validate(struct sk_buff* skb, struct net* net){
    // 获取头部
    const struct SecPathMabAckHeader *sec_path_mab_ack_header;
    // 丢包的原因
    int drop_reason;
    // 总的长度
    u32 len;

    // 进行 pkt_type 的设置 (由于设置的是 BROADCAST_MAC 所以这里不行)
    // 1. PACKET_HOST 代表目的地是本机
    // 2. PACKET_OTHERHOST 代表目的地是其他主机
    skb->pkt_type = PACKET_HOST;

    /* When the interface is in promisc. mode, drop all the crap
     * that it receives, do not try to analyse it
     * 如果是其他主机，那么直接丢
     */
    if (skb->pkt_type == PACKET_OTHERHOST) {
        dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
        drop_reason = SKB_DROP_REASON_OTHERHOST;
        goto drop;
    }

    __IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto out;
    }

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

    // 确保存在足够的空间
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        goto inhdr_error;

    // 解析网络层首部
    sec_path_mab_ack_header = sec_path_mab_ack_hdr(skb);

    /*
     *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
     *
     *	Is the datagram acceptable?
     *
     *	1.	Length at least the size of an ip header
     *	2.	Version of 4
     *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
     *	4.	Doesn't have a bogus length
     */

    BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
    BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
    BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
    __IP_ADD_STATS(net,
                   IPSTATS_MIB_NOECTPKTS + (sec_path_mab_ack_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, sec_path_mab_ack_header->hdr_len))
        goto inhdr_error;

    sec_path_mab_ack_header = sec_path_mab_ack_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) sec_path_mab_ack_header, sec_path_mab_ack_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(sec_path_mab_ack_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (sec_path_mab_ack_header->hdr_len))
        goto inhdr_error;
    // --------------------------------------------------------

    /* Our transport medium may have padded the buffer out. Now we know it
     * is IP we can trim to the true length of the frame.
     * Note this now means skb->len holds ntohs(iph->tot_len).
     */
    if (pskb_trim_rcsum(skb, len)) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto drop;
    }

    sec_path_mab_ack_header = sec_path_mab_ack_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + sec_path_mab_ack_header->hdr_len;

    /* Remove any debris in the socket control block */
    memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    IPCB(skb)->iif = skb->skb_iif;

    /* Must drop socket now because of tproxy. */
    if (!skb_sk_is_prefetched(skb))
        skb_orphan(skb);

    return skb;

    csum_error:
    drop_reason = SKB_DROP_REASON_IP_CSUM;
    __IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
    inhdr_error:
    if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
        drop_reason = SKB_DROP_REASON_IP_INHDR;
    __IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
    drop:
    kfree_skb_reason(skb, drop_reason);
    out:
    return NULL;
}

/**
 * 如果是 normal router 那么直接进行转发, 向不是入接口的接口进行转发
 * @param skb 数据包
 * @param pvs 路径验证结构
 * @param current_ns 当前网络命名空间
 * @param orig_dev 入接口
 */
void sec_path_mab_ack_normal_router_process_ack_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev){
    // 获取当前的 header
    struct SecPathMabAckHeader* sec_path_mab_ack_header = sec_path_mab_ack_hdr(skb);


    //    if(pvs->sec_path_mab_settings->rate_adjust_mode == RATE_ADJUST_MODE_EPOCH) {
    //        int epoch = sec_path_mab_ack_header->epoch;
    //        struct ScheduledCorruptSpecialPacketRatio *entry, *tmp;
    //        list_for_each_entry_safe(entry, tmp, &(pvs->llbmpt->corrupt_special_packet_ratio_entry_list), list) {
    //            if (NULL != entry) {
    //                if (entry->employ_epoch_or_timestamp <= epoch) {
    //                    pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_start = entry->corrupt_special_packet_ratio_start;
    //                    pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_end = entry->corrupt_special_packet_ratio_end;
    //                    list_del(&entry->list);
    //                    kfree(entry);
    //                }
    //            }
    //        }
    //    } else {
    //        u64 time_elapsed_ms = (ktime_get_us() - pvs->sec_path_mab_settings->sync_timestamp) / 1000;
    //        struct ScheduledCorruptSpecialPacketRatio* entry, *tmp;
    //        list_for_each_entry_safe(entry, tmp, &(pvs->llbmpt->corrupt_special_packet_ratio_entry_list), list){
    //            if(NULL != entry){
    //                if(entry->employ_epoch_or_timestamp <= time_elapsed_ms){
    //                    pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_start = entry->corrupt_special_packet_ratio_start;
    //                    pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_end = entry->corrupt_special_packet_ratio_end;
    //                    printk(KERN_EMERG "normal router %d updates corrupt special ratio to [%d, %d] for timestamp %d\n", pvs->node_id,
    //                           entry->corrupt_special_packet_ratio_start, entry->corrupt_special_packet_ratio_end, entry->employ_epoch_or_timestamp);
    //                    list_del(&entry->list);
    //                    kfree(entry);
    //                }
    //            }
    //        }
    //    }

    bool corrupt = false;
    spin_lock_bh(&(pvs->sec_path_mab_settings->lock));
    corrupt = corrupt_decision(pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_start,
                               pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_end);
    spin_unlock_bh(&(pvs->sec_path_mab_settings->lock));

    // 如果决定进行篡改
    if(corrupt){
        struct SecPathMabAckValidationPart* sec_path_mab_ack_validation_part = get_sec_path_mab_ack_validation_part(sec_path_mab_ack_header);
        *(u64*)(sec_path_mab_ack_validation_part->content) += 20;
        sec_path_mab_ack_send_check(sec_path_mab_ack_header);
        printk(KERN_EMERG "corrupt ack packets\n");
    }

    bool packet_forwarded = false;
    int index;
    for(index = 0; index < pvs->abit->number_of_interfaces; index++){
        struct InterfaceTableEntry* ite = pvs->abit->interfaces[index];
        if(ite->ifindex != orig_dev->ifindex){
            pv_packet_forward(skb, ite, current_ns);
            packet_forwarded = true;
            break;
        }
    }
    if(!packet_forwarded) {
        printk(KERN_EMERG "normal router: %d does not forward packet\n", pvs->node_id);
        kfree_skb(skb);
    }
}

/**
 * 如果是路径校验的路由器，那么需要进行路径校验的处理, 进行路径索引的判断, 如果到达目的地就进行本地处理, 否则进行转发
 * @param skb
 * @param pvs
 * @param current_ns
 * @param orig_dev
 * @return
 */
int sec_path_mab_ack_pv_router_process_ack_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* orig_dev){
    // 1. get the ack header
    struct SecPathMabAckHeader* sec_path_mab_ack_header = sec_path_mab_ack_hdr(skb);
    // 2. get the path part
    struct SecPathMabPathPart* path_part = get_sec_path_mab_ack_path_part(sec_path_mab_ack_header);
    // 3. get current hop identifier
    struct SecPathMabHopIdentifier hop_identifier = path_part->hop_identifiers[sec_path_mab_ack_header->current_path_index];
    // printk(KERN_EMERG "length of path: %d | hop identifier link id == %d", sec_path_mab_ack_header->length_of_path, hop_identifier.link_id);
    // 4. judge if reach the final destination
    int destination = sec_path_mab_ack_header->dest;
    bool local_deliver = pvs->node_id == destination;
    if (!local_deliver){
        // 5. find output interface and forward
        int index;
        struct InterfaceTableEntry* output_interface_table_entry = NULL;
        for(index = 0; index < pvs->abit->number_of_interfaces; index++){
            struct InterfaceTableEntry* current_interface_table_entry = pvs->abit->interfaces[index];
            if (current_interface_table_entry->link_identifier == hop_identifier.link_id){
                output_interface_table_entry = current_interface_table_entry;
                break;
            }
        }
        // 6. perform packet forwarding
        if(NULL == output_interface_table_entry){
            printk(KERN_EMERG "cannot find output interface in node %d\n", pvs->node_id);
            kfree_skb(skb);
            return NET_RX_DROP;
        } else {
            // 进行 current_path_index 的更新
            sec_path_mab_ack_header->current_path_index += 1;
            // 进行校验和的更新
            sec_path_mab_ack_send_check(sec_path_mab_ack_header);
            // 进行数据包的转发
            pv_packet_forward(skb, output_interface_table_entry, current_ns);
            return NET_RX_DROP;
        }
    } else {
        return NET_RX_SUCCESS;
    }
}