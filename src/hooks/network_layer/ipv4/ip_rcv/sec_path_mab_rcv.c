#include <net/inet_ecn.h>
#include <linux/inetdevice.h>
#include "structure/namespace/namespace.h"
#include "structure/header/sec_path_mab_header.h"
#include "structure/routing/linked_list_based_malicious_params_table.h"
#include "types/router_types.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"


int sec_path_mab_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    struct net *current_ns = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    struct SecPathMabHeader *sec_path_mab_header = sec_path_mab_hdr(skb);
    // 1. 初始化变量
    int process_result;
    // 2. 进行初级的校验
    skb = sec_path_mab_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    // 3. 根据不同的路由器的类型执行不同的操作
    if (pvs->router_type == ROUTER_TYPE_NORMAL) { // 3.1 一般的路由器的处理
        //        printk(KERN_EMERG "normal router %d receives packet\n", pvs->node_id);
        // 3.1.1 进行数据包的处理
        sec_path_mab_normal_router_process_data_packets(skb, pvs, current_ns, orig_dev);
        // 3.1.2 不可能接收直接返回
        return 0;
    } else if (pvs->router_type == ROUTER_TYPE_PATH_VALIDATION) { // 3.2 诚实的路径验证路由器的处理
        //        printk(KERN_EMERG "path validation router %d receives packet\n", pvs->node_id);
        // 3.2.1 进行不同的数据包的处理
        process_result = sec_path_mab_pv_router_process_data_packets(skb, pvs, current_ns, orig_dev);
        // 3.2.2 进行数据包本地的处理
        if (NET_RX_SUCCESS == process_result) {
            __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
            pv_local_deliver(skb, sec_path_mab_header->protocol, receive_interface_address);
        }
        return 0;
    } else {
        printk(KERN_EMERG "invalid router type: %d\n", pvs->router_type);
        kfree_skb(skb);
        return 0;
    }
}

struct sk_buff *sec_path_mab_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct SecPathMabHeader *sec_path_mab_header;
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
    sec_path_mab_header = sec_path_mab_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (sec_path_mab_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, sec_path_mab_header->hdr_len))
        goto inhdr_error;

    sec_path_mab_header = sec_path_mab_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) sec_path_mab_header, sec_path_mab_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(sec_path_mab_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (sec_path_mab_header->hdr_len))
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

    sec_path_mab_header = sec_path_mab_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + sec_path_mab_header->hdr_len;

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
 * 凭证校验的流程
 * @param hash_api
 * @param hmac_api
 * @param static_fields_hash
 * @param pvf_start_pointer
 * @param hvf_start_pointer
 * @param session_key
 * @param timestamp
 * @param current_path_index
 * @param hvfs_size
 * @return
 */
static struct VerificationResult proof_verification(struct shash_desc *hash_api,
                                                    struct shash_desc *hmac_api,
                                                    unsigned char *static_fields_hash,
                                                    unsigned char *pvf_start_pointer,
                                                    unsigned char *hvf_start_pointer,
                                                    char *session_key,
                                                    struct TimeStamp *timestamp,
                                                    int current_path_index,
                                                    int hvfs_size,
                                                    int node_id) {
    struct VerificationResult verification_result = {
            .rcv_packet_type = RCV_ERROR_PACKET,
            .sample_identifier = NULL,
    };

    int hvf_length = sizeof(struct MabHvf);

    // 1. get combination
    int current_offset = 0;
    unsigned char combination[200] = {0};
    // 1.1 combine pvf
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    current_offset += PVF_LENGTH;
    // 1.2 combine hvfs
    unsigned char *hvf_start_copy_pointer = hvf_start_pointer + sizeof(struct MabHvf) * (current_path_index + 1);
    int copied_size = sizeof(struct MabHvf) * (hvfs_size - (current_path_index + 1));
    memcpy(combination + current_offset, hvf_start_copy_pointer, copied_size);
    current_offset += copied_size;
    // 1.3 combine hash
    memcpy(combination + current_offset, static_fields_hash, HASH_LENGTH);
    current_offset += HASH_LENGTH;
    // 1.4 combine timestamp
    memcpy(combination + current_offset, timestamp, sizeof(struct TimeStamp));
    current_offset += sizeof(struct TimeStamp);

    // 1.5 print the combination
    //    if (9 == node_id) {
    //        printk(KERN_EMERG "---------------------- received combination ----------------------\n");
    //        print_memory_in_hex(combination, current_offset);
    //        printk(KERN_EMERG "---------------------- received combination ----------------------\n");
    //    }

    // 2. calculate HVF
    unsigned char *expected_hvf = calculate_hmac(hmac_api,
                                                 combination,
                                                 current_offset,
                                                 (unsigned char *) session_key,
                                                 (int) strlen(session_key));

    // 3. perform comparison
    struct MabHvf *hvfs = (struct MabHvf *) (hvf_start_pointer);
    bool first_comparison_result = memory_compare((unsigned char *) (&(hvfs[current_path_index])), expected_hvf,
                                                  hvf_length);

    bool second_comparison_result = false;

    // 4. perform sampling comparison
    if (first_comparison_result) {
        // printk(KERN_EMERG "first comparison success, no need to do sampling comparison\n");
        verification_result.rcv_packet_type = RCV_DATA_PACKET;
    } else {
        // calculate sample identifier combination
        int length_of_session_key = (int) strlen(session_key);
        unsigned char sample_identifier_combination[HASH_OUTPUT_LENGTH + length_of_session_key];
        memcpy(sample_identifier_combination, static_fields_hash, HASH_OUTPUT_LENGTH);
        memcpy(sample_identifier_combination + HASH_OUTPUT_LENGTH, session_key, length_of_session_key);
        // calculate sample identifier
        unsigned char *sample_identifier = calculate_hash(hash_api,
                                                          sample_identifier_combination,
                                                          HASH_OUTPUT_LENGTH + length_of_session_key);
        // make a copy of sample identifier
        unsigned char* sample_identifier_copy = (unsigned char*)kmalloc(sizeof(unsigned char) * HASH_OUTPUT_LENGTH, GFP_ATOMIC);
        memcpy(sample_identifier_copy, sample_identifier, HASH_OUTPUT_LENGTH);

        // calculate current result and sample identifier (the length of sample identifier is HASH_OUTPUT_LENGTHS)
        memory_xor(sample_identifier, (unsigned char *) &(hvfs[current_path_index]), hvf_length);

        // perform memory compare
        second_comparison_result = memory_compare(sample_identifier, expected_hvf, hvf_length);

        // free the sample identifier result
        if(NULL != sample_identifier){
            kfree(sample_identifier);
        }

        // determine which packet type
        if (second_comparison_result) {
            verification_result.rcv_packet_type = RCV_SAMPLE_PACKET;
            verification_result.sample_identifier = sample_identifier_copy; // 只有在 sample 的时候 verification_result 的 sample_identifier 才需要进行释放
            // printk(KERN_EMERG "first comparison failed but second comparison success, treat as sample packet\n");
        } else {
            verification_result.rcv_packet_type = RCV_ERROR_PACKET;
            // printk(KERN_EMERG "node %d first comparison failed and second comparison failed, treat as error packet\n", node_id);
            // free the memory of sample_identifier_copy
            if(NULL != sample_identifier_copy){
                kfree(sample_identifier_copy);
            }
        }
    }

    // 5. free expected hvf
    if (NULL != expected_hvf) {
        kfree(expected_hvf);
    }
    return verification_result;
}


// 进行更新后的 pvf 的计算
static unsigned char *calculate_updated_proof(struct shash_desc *hmac_api,
                                              char *session_key,
                                              unsigned char *pvf_start_pointer) {
    // 1. calculate mac with session key
    unsigned char *hmac_result = calculate_hmac(hmac_api,
                                                pvf_start_pointer,
                                                PVF_LENGTH,
                                                (unsigned char *) session_key,
                                                (int) strlen(session_key));

    // 2. return the result
    return hmac_result;
}

// 将更新完成之后的 pvf 设置到数据包之中
static void set_updated_proof(unsigned char *updated_pvf, unsigned char *pvf_start_pointer) {
    memcpy(pvf_start_pointer, updated_pvf, PVF_LENGTH);
}

/* 假设 start 和 end 已经被放大 1000000 倍的整数
   例如: start = 100000 (代表 10%)
*/

/**
 * 普通的路由器应该怎么进行转发的执行 (寻找除入接口以外的第一个接口进行转发)
 * @param skb
 * @param pvs
 * @param current_ns
 * @param orig_dev
 */
void sec_path_mab_normal_router_process_data_packets(struct sk_buff *skb, struct PathValidationStructure *pvs,
                                                     struct net *current_ns, struct net_device *orig_dev) {

    // 获取当前的 header
    struct SecPathMabHeader* sec_path_mab_header = sec_path_mab_hdr(skb);

    //    if(pvs->sec_path_mab_settings->rate_adjust_mode == RATE_ADJUST_MODE_EPOCH){
    //        int epoch = sec_path_mab_header->epoch;
    //        struct ScheduledCorruptRatio* entry, *tmp;
    //        list_for_each_entry_safe(entry, tmp, &(pvs->llbmpt->corrupt_ratio_entry_list), list){
    //            if(NULL != entry){
    //                if(entry->employ_epoch_or_timestamp <= epoch){
    //                    pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_start = entry->corrupt_ratio_start;
    //                    pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_end = entry->corrupt_ratio_end;
    //                    printk(KERN_EMERG "normal router %d updates corrupt ratio to [%d, %d] for epoch %d\n", pvs->node_id,
    //                           entry->corrupt_ratio_start, entry->corrupt_ratio_end, entry->employ_epoch_or_timestamp);
    //                    list_del(&entry->list);
    //                    kfree(entry);
    //                }
    //            }
    //        }
    //    } else {
    //    struct ScheduledCorruptRatio* entry, *tmp;
    //    list_for_each_entry_safe(entry, tmp, &(pvs->llbmpt->corrupt_ratio_entry_list), list){
    //        if(NULL != entry){
    //            if(pvs->sec_path_mab_settings->sync_timestamp + entry->employ_epoch_or_timestamp * 1000 <= ktime_get_us()){
    //                pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_start = entry->corrupt_ratio_start;
    //                pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_end = entry->corrupt_ratio_end;
    //                printk(KERN_EMERG "sync_timestamp: {%llu}, employ_epoch_or_timestamp: {%llu}, current time: {%llu} \n", pvs->sec_path_mab_settings->sync_timestamp,
    //                       entry->employ_epoch_or_timestamp * 1000, ktime_get_us());
    //                list_del(&entry->list);
    //                kfree(entry);
    //            }
    //        }
    //    }
            //  u64 time_elapsed_ms = (ktime_get_us() - pvs->sec_path_mab_settings->sync_timestamp) / 1000;
    //    }
    //    bool corrupt = corrupt_decision(pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_start,
    //                                    pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_end);
    //    if (corrupt) {
    //        // 获取 hvfs 的最后一个进行修改
    //        struct SecPathMabValidationPart *sec_path_mab_validation_part = get_sec_path_mab_validation_part(
    //                sec_path_mab_header, sec_path_mab_header->length_of_path);
    //        *((u16 *) &(sec_path_mab_validation_part->hvfs[sec_path_mab_header->length_of_path])) += 20;
    //        sec_path_mab_send_check(sec_path_mab_header);
    //    }


    bool corrupt = false;
    spin_lock_bh(&(pvs->sec_path_mab_settings->lock));
    corrupt = corrupt_decision(pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_start,
                                    pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_end);
    spin_unlock_bh(&(pvs->sec_path_mab_settings->lock));
    if (corrupt) {
        // 获取 hvfs 的最后一个进行修改
        struct SecPathMabValidationPart *sec_path_mab_validation_part = get_sec_path_mab_validation_part(
                sec_path_mab_header, sec_path_mab_header->length_of_path);
        *((u16 *) &(sec_path_mab_validation_part->hvfs[sec_path_mab_header->length_of_path])) += 20;
        sec_path_mab_send_check(sec_path_mab_header);
    }

    // 进行转发还是篡改
    bool packet_forwarded = false;
    int index;
    for (index = 0; index < pvs->abit->number_of_interfaces; index++) {
        struct InterfaceTableEntry *ite = pvs->abit->interfaces[index];
        if (ite->ifindex != orig_dev->ifindex) {
            pv_packet_forward(skb, ite, current_ns);
            packet_forwarded = true;
            break;
        }
    }
    // 如果转发没有成功的话, 那么就丢掉这个包
    if (!packet_forwarded) {
        printk(KERN_EMERG "normal router: %d does not forward packet\n", pvs->node_id);
        kfree_skb(skb);
    }
}

/**
 * 进行 ack 的回送
 * @param received_skb
 * @param verification_result
 * @param incoming_interface_table_entry
 * @param current_path_index
 */
static void send_ack_packet_back_to_source(struct sk_buff *received_skb,
                                           struct VerificationResult *verification_result,
                                           struct InterfaceTableEntry *incoming_interface_table_entry,
                                           int current_path_index) {
    // 1. create ack packet from received skb
    struct sk_buff *ack_packet = self_defined_make_sec_path_mab_ack_skb(received_skb,
                                                                        verification_result->sample_identifier,
                                                                        incoming_interface_table_entry,
                                                                        current_path_index);
    // 2. forward ack packet back to the source
    pv_packet_forward(ack_packet,
                      incoming_interface_table_entry,
                      dev_net(incoming_interface_table_entry->interface));
}

/**
 * 进行 data 的转发
 * @param skb
 * @param updated_pvf
 * @param sec_path_mab_header
 * @param incoming_interface_table_entry
 * @param output_interface_table_entry
 * @param current_ns
 */
static void forward_data_packet(struct sk_buff *skb,
                                unsigned char *updated_pvf,
                                struct SecPathMabHeader *sec_path_mab_header,
                                struct InterfaceTableEntry *incoming_interface_table_entry,
                                struct InterfaceTableEntry *output_interface_table_entry,
                                struct net *current_ns) {
    // 1. get part
    struct SecPathMabValidationPart *validation_part = get_sec_path_mab_validation_part(sec_path_mab_header,
                                                                                        sec_path_mab_header->length_of_path);
    struct SecPathMabPathPart *path_part = get_sec_path_mab_path_part(sec_path_mab_header);
    // 2. set the pvf into the packet header
    set_updated_proof(updated_pvf, (unsigned char *) (&validation_part->pvf));
    // 3. update path part
    path_part->hop_identifiers[sec_path_mab_header->current_path_index].incoming_link_id = incoming_interface_table_entry->link_identifier;
    // 4. increase current path index (current path index should be increased after updating the hop identifiers)
    sec_path_mab_header->current_path_index++;
    // 5. checksum update
    sec_path_mab_send_check(sec_path_mab_header);
    // 6. forward the packet
    pv_packet_forward(skb, output_interface_table_entry, current_ns);
}

/**
 * 路径校验路由器进行转发的流程
 * @param skb
 * @param pvs
 * @param current_ns
 * @param orig_dev
 * @return
 */
int sec_path_mab_pv_router_process_data_packets(struct sk_buff *skb, struct PathValidationStructure *pvs,
                                                struct net *current_ns, struct net_device *orig_dev) {
    // 1. final result
    int final_result = NET_RX_DROP;
    // 2. get session key
    char session_key[20] = {0};
    snprintf(session_key, sizeof(session_key), "key-%d", pvs->node_id);
    // 2. get header
    struct SecPathMabHeader *sec_path_mab_header = sec_path_mab_hdr(skb);
    // 3. get information
    int destination = sec_path_mab_header->dest;
    bool local_deliver = pvs->node_id == destination;
    struct SecPathMabMetadata *metadata = get_sec_path_mab_metadata(sec_path_mab_header);
    struct SecPathMabPathPart *path_part = get_sec_path_mab_path_part(sec_path_mab_header);
    struct SecPathMabValidationPart *validation_part = get_sec_path_mab_validation_part(sec_path_mab_header,
                                                                                        sec_path_mab_header->length_of_path);
    // 4. get output link and incoming link id
    // find output interface and incoming id
    // -------------------------------------------------------------------------------------------------------------
    struct InterfaceTableEntry *output_interface_table_entry = NULL;
    struct InterfaceTableEntry *incoming_interface_table_entry = NULL;
    bool find_output = false;
    bool find_incoming = false;
    if (!local_deliver) {
        // find output and incoming interface
        output_interface_table_entry = find_ite_in_abit_with_link_identifier(pvs->abit,
                                                                             path_part->hop_identifiers[sec_path_mab_header->current_path_index].link_id);
        if (NULL != output_interface_table_entry) {
            find_output = true;
        }
        incoming_interface_table_entry = find_ite_in_abit_with_ifindex(pvs->abit, orig_dev->ifindex);
        if (NULL != incoming_interface_table_entry) {
            find_incoming = true;
        }

        if (!(find_output && find_incoming)) {
            printk(KERN_EMERG "on-path router cannot find output interface or incoming link id\n");
            kfree_skb(skb);
            final_result = NET_RX_DROP;
            return final_result;
        }
    } else {
        // find incoming interface only
        incoming_interface_table_entry = find_ite_in_abit_with_ifindex(pvs->abit, orig_dev->ifindex);
        if (NULL != incoming_interface_table_entry) {
            find_incoming = true;
        }
        if (!find_incoming) {
            printk(KERN_EMERG "destination cannot find incoming interface\n");
            kfree_skb(skb);
            final_result = NET_RX_DROP;
            return final_result;
        }
    }
    // -------------------------------------------------------------------------------------------------------------
    // 5. get pv struct
    //    struct pv_struct *p = get_cpu_ptr(&validation_api);
    //    struct pv_struct p_node = create_pv_struct(true, true, false, NULL);
    //    struct pv_struct *p = &p_node;

    // 5. 禁止下半部中断
    local_bh_disable();
    struct pv_struct *p = get_cpu_ptr(&validation_api);

    // 6. calculate hash
    unsigned char *static_fields_hash = calculate_sec_path_mab_hash(p->hash_api, sec_path_mab_header, &(metadata->timestamp));
    // 7. verification
    struct VerificationResult verification_result = proof_verification(p->hash_api,
                                                                       p->hmac_api,
                                                                       static_fields_hash,
                                                                       (unsigned char *) &(validation_part->pvf),
                                                                       (unsigned char *) &(validation_part->hvfs),
                                                                       session_key,
                                                                       &(metadata->timestamp),
                                                                       sec_path_mab_header->current_path_index,
                                                                       sec_path_mab_header->length_of_path + 1,
                                                                       pvs->node_id);
    // 7. free hash
    if (NULL != static_fields_hash) {
        kfree(static_fields_hash);
    }
    // 8. process packet
    if (local_deliver) {
        if (verification_result.rcv_packet_type == RCV_DATA_PACKET) {
            // 0. 如果成功了就交给上层
            final_result = NET_RX_SUCCESS;
        } else if (verification_result.rcv_packet_type == RCV_SAMPLE_PACKET) {
            // 1. get updated pvf
            unsigned char *updated_pvf = calculate_updated_proof(p->hmac_api, session_key,
                                                                 (unsigned char *) &(validation_part->pvf));
            // 2. perform xor operation
            memory_xor(verification_result.sample_identifier, updated_pvf, PVF_LENGTH);

            // 3. send ack back to source

            //            printk(KERN_EMERG "------------------------ received identifier: %d --------------------\n", sec_path_mab_header->identifier);
            //            print_memory_in_hex(verification_result.sample_identifier, ACK_AUTHENTICATION_LENGTH);
            //            print_memory_in_hex((unsigned char *) &(validation_part->pvf), PVF_LENGTH);
            //            print_memory_in_hex(updated_pvf, PVF_LENGTH);
            //            printk(KERN_EMERG "session_key: %s, len: %d\n", session_key, (int)strlen(session_key));
            //            printk(KERN_EMERG "------------------------ received identifier: %d --------------------\n", sec_path_mab_header->identifier);

            send_ack_packet_back_to_source(skb, &verification_result, incoming_interface_table_entry, sec_path_mab_header->current_path_index);


            // 4. free result
            if (NULL != updated_pvf) {
                kfree(updated_pvf);
            }
            if (NULL != verification_result.sample_identifier) {
                kfree(verification_result.sample_identifier);
            }

            // 5. set the final result
            final_result = NET_RX_SUCCESS;
        } else {
            kfree_skb(skb);
            final_result = NET_RX_DROP;
        }
    } else {
        if (verification_result.rcv_packet_type == RCV_DATA_PACKET) {
            // 1. update packet
            unsigned char *updated_pvf = calculate_updated_proof(p->hmac_api, session_key,
                                                                 (unsigned char *) &(validation_part->pvf));
            // 2. forward data packet
            forward_data_packet(skb, updated_pvf, sec_path_mab_header,
                                incoming_interface_table_entry, output_interface_table_entry, current_ns);

            // 3. free kmalloc
            if (NULL != updated_pvf) {
                kfree(updated_pvf);
            }
            // 4. set the final result
            final_result = NET_RX_DROP;
        } else if (verification_result.rcv_packet_type == RCV_SAMPLE_PACKET) {
            // 1. update packet
            unsigned char *updated_pvf = calculate_updated_proof(p->hmac_api, session_key, (unsigned char*)&(validation_part->pvf));
            // 2. xor content
            memory_xor(verification_result.sample_identifier, updated_pvf, PVF_LENGTH);

            //            printk(KERN_EMERG "------------------------ received identifier: %d --------------------\n", sec_path_mab_header->identifier);
            //            print_memory_in_hex(verification_result.sample_identifier, ACK_AUTHENTICATION_LENGTH);
            //            print_memory_in_hex((unsigned char *) &(validation_part->pvf), PVF_LENGTH);
            //            print_memory_in_hex(updated_pvf, PVF_LENGTH); // updated pvf 计算错误
            //            printk(KERN_EMERG "session_key: %s, len: %d\n", session_key, (int)strlen(session_key));
            //            printk(KERN_EMERG "------------------------ received identifier: %d --------------------\n", sec_path_mab_header->identifier);

            // 3. send_ack_back_to_source
            send_ack_packet_back_to_source(skb, &verification_result, incoming_interface_table_entry, sec_path_mab_header->current_path_index);

            // 4. forward data packet
            forward_data_packet(skb, updated_pvf, sec_path_mab_header,
                                incoming_interface_table_entry,
                                output_interface_table_entry,
                                current_ns);

            // 5. free the memory
            if (NULL != updated_pvf) {
                kfree(updated_pvf);
            }
            if (NULL != verification_result.sample_identifier) {
                kfree(verification_result.sample_identifier);
            }
            // 6. set the final result
            final_result = NET_RX_DROP;
        } else {
            kfree_skb(skb);
            final_result = NET_RX_DROP;
        }
    }

    // 9. 进行 percpu struct 的释放
    put_cpu_ptr(p);
    local_bh_enable();

    // 9. free pv struct
    //    put_cpu_ptr(p);
    //    free_pv_struct(p);
    // 10. return final result
    return final_result;
}