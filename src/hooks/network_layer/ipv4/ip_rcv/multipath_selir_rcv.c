#include <net/inet_ecn.h>
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/header/multipath_selir_header.h"
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "structure/routing/array_based_multipath_table.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include <linux/inetdevice.h>

int multipath_fast_selir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
                             struct net_device *orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed,
                             u64* find_segments_time_elapsed) {
    // 1. 初始化变量
    struct net *net = dev_net(dev);
    struct MultipathSELiRHeader *fast_selir_header = multipath_selir_hdr(skb);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    int process_result;

    // 2. 进行初级的校验
    skb = multipath_fast_selir_rcv_validate(skb, net);
    if (NULL == skb) {
        LOG_WITH_PREFIX("validation failed");
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // 3. 进行实际的转发
    process_result = multipath_fast_selir_forward_packets(skb, pvs, net, orig_dev,
                                                          intermediate_verification_time_elapsed, destination_verification_time_elapsed,
                                                          find_segments_time_elapsed);

    // 4. 进行最后的检查
    if (NET_RX_SUCCESS == process_result) {
        // 4.1 数据包向上层进行提交
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, fast_selir_header->protocol, receive_interface_address);
    }

    return 0;
}


struct sk_buff *multipath_fast_selir_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct MultipathSELiRHeader *multipath_selir_header;
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
    multipath_selir_header = multipath_selir_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (multipath_selir_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, multipath_selir_header->hdr_len))
        goto inhdr_error;

    multipath_selir_header = multipath_selir_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) multipath_selir_header, multipath_selir_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(multipath_selir_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (multipath_selir_header->hdr_len))
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

    multipath_selir_header = multipath_selir_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + multipath_selir_header->hdr_len;

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

static bool intermediate_proof_verification(struct PathValidationStructure *pvs,
                                            unsigned char *pvf_start_pointer, unsigned char *ppf_start_pointer,
                                            unsigned char *static_fields_hash,
                                            struct shash_desc *hmac_api,
                                            struct BloomFilter *bloom_filter) {

//    LOG_WITH_EDGE("pvf value");
//    print_memory_in_hex(pvf_start_pointer, PVF_LENGTH);
//    LOG_WITH_EDGE("pvf value");
//
//    LOG_WITH_EDGE("static fields hash");
//    print_memory_in_hex(static_fields_hash, HASH_LENGTH);
//    LOG_WITH_EDGE("static fields hash");


    // 判断结果
    bool validation_result = false;


    // 进行布隆过滤器的修改
    unsigned char *original_bit_set = bloom_filter->bitset;
    bloom_filter->bitset = ppf_start_pointer;

    // 构造 combination
    unsigned char combination[PVF_LENGTH + HASH_LENGTH] = {0};
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);

    // 拿到  key
    char key[20];
    snprintf(key, sizeof(key), "key-%d", pvs->node_id);

    // 根据 combination 进行 next pvf 的计算
    unsigned char *next_pvf = calculate_hmac(hmac_api,
                                             combination,
                                             PVF_LENGTH + HASH_LENGTH,
                                             (unsigned char *) key,
                                             (int) strlen(key));

//    LOG_WITH_EDGE("pvf");
//    print_memory_in_hex(next_pvf, PVF_LENGTH);
//    LOG_WITH_EDGE("pvf");

    // 判断是否在其中
    if (0 == check_element_in_bloom_filter(bloom_filter, next_pvf, 16)) {
        validation_result = true;
    }

    // 进行布隆过滤器的还原
    bloom_filter->bitset = original_bit_set;

    // 进行 pvf 的更新
    memcpy(pvf_start_pointer, next_pvf, PVF_LENGTH);

    // 进行 next pvf 的释放
    kfree(next_pvf);

    // 返回结果
    return validation_result;
}

static bool destination_proof_verification(struct PathValidationStructure *pvs, unsigned char *env_pvf_start_pointer,
                                           unsigned char *static_fields_hash, unsigned char *pvf_start_pointer,
                                           struct shash_desc *hmac_api) {
    // 1. 构建 combination
    unsigned char combination[PVF_LENGTH + HASH_LENGTH] = {0};
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(combination + PVF_LENGTH, static_fields_hash, HASH_LENGTH);

    // 拿到  key
    char key[20];
    snprintf(key, sizeof(key), "key-%d", pvs->node_id);

    // 根据 combination 进行 next pvf 的计算
    unsigned char *next_pvf = calculate_hmac(hmac_api,
                                             combination,
                                             PVF_LENGTH + HASH_LENGTH,
                                             (unsigned char *) key,
                                             (int) strlen(key));

    // 判断是否和包内的 enc_pvf 一致
    bool result = memory_compare(env_pvf_start_pointer, next_pvf, ENC_PVF_LENGTH);

    // 进行释放 Hmac
    kfree(next_pvf);

    return result;
}


int
multipath_fast_selir_forward_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                                     struct net_device *in_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed, u64* find_segments_time) {
    // 最终结果
    int final_result;
    // 首部
    struct MultipathSELiRHeader *multipath_selir_header = multipath_selir_hdr(skb);
    // ------------------------------------------- 验证流程 -------------------------------------------
    // 拿到 各个部分的指针
    unsigned char *pvf_start_pointer = get_multipath_selir_pvf_start_pointer(multipath_selir_header);
    unsigned char *ppf_start_pointer = get_multipath_selir_ppf_start_pointer(multipath_selir_header, multipath_selir_header->number_of_paths);
    unsigned char *selected_path_start_pointer = get_possible_path_ids_start_pointer(multipath_selir_header);

    // 获取 hash_api 和 hmac_api
    // ---------------------------------------------------------------------------------------
    struct pv_struct *p = get_cpu_ptr(&validation_api);
//    struct pv_struct p = create_pv_struct(true, true, true, pvs->bloom_filter);
    // ---------------------------------------------------------------------------------------

    // 进行哈希值的计算
    unsigned char *static_fields_hash = calculate_multipath_selir_hash(p->hash_api, multipath_selir_header);
    // 如果非目的节点则进行中间节点的校验逻辑
    bool verification_result = false;
    if (pvs->node_id != multipath_selir_header->destination) {

        u64 start_find_segment_time = ktime_get_real_ns();

        // 选择的接口
        struct InterfaceTableEntry *selected_ite = NULL;
        struct OutputInterfaceToPathsMapping *selected_mapping = NULL;
        // 进行各个 segments 的遍历
        if (pvs->abpt->number_of_interface_to_path_mappings == 0) {
            // 首先查看是否有可选的出接口
            selected_ite = find_output_interface_in_abpt_for_multipath_selir(pvs->abpt, pvs->abit,
                                                                             multipath_selir_header->destination);
        } else {
            int mapping_index = 0;
            int count = 0;
            struct OutputInterfaceToPathsMapping **available_mappings = (struct OutputInterfaceToPathsMapping **) kmalloc(
                    sizeof(struct OutputInterfaceToPathsMapping *) * 10, GFP_KERNEL);
            for (mapping_index = 0; mapping_index < pvs->abpt->number_of_interface_to_path_mappings; mapping_index++) {
                unsigned char *bit_set = pvs->abpt->output_interface_to_path_mappings[mapping_index]->bit_set;
                int inner_index;
                int total = 0;
                for (inner_index = 0; inner_index < multipath_selir_header->selected_paths_part_size; inner_index++) {
                    // printk_binary_u8(bit_set[inner_index]);
                    total += selected_path_start_pointer[inner_index] & bit_set[inner_index];
                }
                if (total == 0) {
                    continue;
                } else {
                    available_mappings[count++] = pvs->abpt->output_interface_to_path_mappings[mapping_index];
                }
            }

            // printk(KERN_EMERG "available mappings %d\n", count);

            if(0 == count){
                selected_mapping  = NULL;
            } else {
                // 根据转发的数据包的大小决定一下从选择的哪个里面转发
                u32 round_robin_selection = (get_random_u32()) % (count);
                // printk(KERN_EMERG "round robin selection = %d\n", round_robin_selection);
                // 选择的 mapping--
                selected_mapping = available_mappings[round_robin_selection];
            }
            // 进行待选数组的释放
            kfree(available_mappings);
            // selected_mapping != NULL
        }

        *find_segments_time = ktime_get_real_ns() - start_find_segment_time;

        u64 intermediate_verification_start_time = ktime_get_real_ns();

        // 如果没有可选的出接口那么直接进行丢包然后返回
        if ((NULL == selected_ite) && (NULL == selected_mapping)) {
            printk(KERN_EMERG "node %d cannot find output interface\n", pvs->node_id);
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            final_result = NET_RX_DROP;
        } else {
            // 验证结果
            verification_result = intermediate_proof_verification(pvs, pvf_start_pointer, ppf_start_pointer,
                                                                  static_fields_hash, p->hmac_api, p->bloom_filter);
            if (verification_result) {
                // 进行跳数量更新
                multipath_selir_header->current_path_index += 1;
                // 打印校验结果
                // printk(KERN_EMERG "node %d verification succeed!\n", pvs->node_id);
                // 进行数据包的转发
                if (NULL != selected_ite) {
                    multipath_selir_send_check(multipath_selir_header);
                    pv_packet_forward(skb, selected_ite, current_ns);
                } else {
                    int current_index = 0;
                    // LOG_WITH_EDGE("update selected path");
                    for (current_index = 0; current_index < multipath_selir_header->selected_paths_part_size; current_index++) {
                        selected_path_start_pointer[current_index] = selected_path_start_pointer[current_index] & selected_mapping->bit_set[current_index];
                        // printk_binary_u8(selected_path_start_pointer[current_index]);
                    }
                    // LOG_WITH_EDGE("update selected path");
                    multipath_selir_send_check(multipath_selir_header);
                    pv_packet_forward(skb, selected_mapping->ite, current_ns);
                }
                final_result = NET_RX_DROP;
            } else {
                printk(KERN_EMERG "node %d verification failed!\n", pvs->node_id);
                // free packet
                kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
                final_result = NET_RX_DROP;
            }
        }

        *intermediate_verification_time_elapsed = ktime_get_real_ns() - intermediate_verification_start_time;
    } else {
        u64 find_segments_start_time = ktime_get_real_ns();

        int dest_pvf_index;
        for(dest_pvf_index = 0; dest_pvf_index < multipath_selir_header->selected_paths_part_size * 8; dest_pvf_index++){
            if (test_bit(dest_pvf_index, (unsigned long*)(selected_path_start_pointer))){
                //printk(KERN_EMERG "dest pvf index = %d\n", dest_pvf_index);
                break;
            }
        }

        *find_segments_time = ktime_get_real_ns() - find_segments_start_time;

        u64 destination_verification_start_time = ktime_get_real_ns();

        // 如果能够找到则根据 rte->index 找到对应的 encpvf
        unsigned char *enc_pvf_start_pointer = get_multipath_selir_ith_dvf_start_pointer(multipath_selir_header,
                                                                                         dest_pvf_index);
        verification_result = destination_proof_verification(pvs, enc_pvf_start_pointer, static_fields_hash,
                                                             pvf_start_pointer, p->hmac_api);
        if (verification_result) {
            final_result = NET_RX_SUCCESS;
            // printk(KERN_EMERG "destination verification succeed!\n");
        } else {
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
            final_result = NET_RX_DROP;
            printk(KERN_EMERG "destination verification failed!\n");
        }
        *destination_verification_time_elapsed = ktime_get_real_ns() - destination_verification_start_time;
    }
    // ------------------------------------------- 验证流程 -------------------------------------------

    // 进行哈希值的释放
    kfree(static_fields_hash);

    // 释放 p
//    free_pv_struct(&p);
    put_cpu_ptr(p);

    return final_result;
}