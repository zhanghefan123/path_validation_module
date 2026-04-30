#include <net/inet_ecn.h>
#include <linux/inetdevice.h>
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/header/epic_fields_length.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

int epic_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed){
    struct net *net = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    struct EpicHeader* epic_header = epic_hdr(skb);
    int process_result;

    // 2. 进行初级的(无需密码学)校验
    skb = epic_rcv_validate(skb, net);
    if(NULL == skb){
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // 3. 进行实际的(带有密码学)的校验和转发
    process_result = epic_forward_packets(skb, pvs, net, orig_dev, intermediate_verification_time_elapsed, destination_verification_time_elapsed);

    // 4. 判断是本地交付还是直接丢弃
    if(NET_RX_SUCCESS == process_result) {
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, epic_header->protocol,
                         receive_interface_address);
    }

    return 0;
}

struct sk_buff* epic_rcv_validate(struct sk_buff* skb, struct net* net){
    // 获取头部
    const struct EpicHeader *epic_header;
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
    epic_header = epic_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (epic_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, epic_header->hdr_len))
        goto inhdr_error;

    epic_header = epic_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) epic_header, epic_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(epic_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (epic_header->hdr_len))
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

    epic_header = epic_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + epic_header->hdr_len;

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

// 中间节点的校验过程
static bool intermediate_proof_verification(struct EpicHeader* epic_header, struct PathValidationStructure* pvs, struct EpicPathPart* path_part,
        struct EpicValidationPart* validation_part, struct shash_desc* hmac_api){
    /*
    int index = 0;
    print_memory_in_hex((unsigned char*)path_part, get_epic_header_path_part_size(epic_header->length_of_path-1));
    print_memory_in_hex((unsigned char*)validation_part, get_epic_header_validation_part_size(epic_header->length_of_path-1));
    print_memory_in_hex((unsigned char*)path_part, get_epic_header_path_part_size(epic_header->length_of_path-1) + get_epic_header_validation_part_size(epic_header->length_of_path-1));
    return false;
     */
    // 1.最后的结果
    bool result = true;
    // 2.进行 as-level-key 的构造
    char key[20];
    snprintf(key, sizeof(key), "key-%d", pvs->node_id);
    // 3.获取当前索引
    int current_path_index = epic_header->current_path_index;
    // 4.构造 concatenation
    // ----------------------------------------------------------------------------------------------------------
    unsigned char concatenation[PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH + SEGMENT_IDENTIFIER_LENGTH] = {0};
    // 4.1. 拼时间戳
    memcpy(concatenation, &(path_part->path_part_meta.path_time_stamp), PATH_TIMESTAMP_LENGTH);
//    printk(KERN_EMERG "intermediate received timestamp: %llu", path_part->path_part_meta.path_time_stamp); // 时间是对的
    // 4.2. 拼 HI
    memcpy(concatenation + PATH_TIMESTAMP_LENGTH, &(path_part->hop_identifiers[current_path_index]), HOP_IDENTIFIER_LENGTH);
    // 4.3. 拼 segment identifier a->b->c->d->e 到 b 的时候就没有前驱的 segment identifier 了, 到 b 的时候的 current_path_index == 1, length_of_path = 3
    if (current_path_index != (epic_header->length_of_path-2))  {
        memcpy(concatenation + PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH, &(validation_part->validationHops[current_path_index+1].segment_identifier), SEGMENT_IDENTIFIER_LENGTH);
    }
    // ----------------------------------------------------------------------------------------------------------

    // 5.进行 hop authenticator 的还原
    // ----------------------------------------------------------------------------------------------------------
    unsigned char* hop_authenticator = calculate_hmac(hmac_api,
                                                      concatenation,
                                                      PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH + SEGMENT_IDENTIFIER_LENGTH,
                                                      (unsigned char*)key,
                                                      (int)(strlen(key))); // hop_authenticator 是对的
    // ----------------------------------------------------------------------------------------------------------
    int index;
//    LOG_WITH_PREFIX("SEGMENT IDENTIFIERS");
//    for (index = 0; index < (epic_header->length_of_path - 1); index++){
//        print_memory_in_hex((unsigned char *) &(validation_part->validationHops[index].segment_identifier), SEGMENT_IDENTIFIER_LENGTH);
//    }
//    print_memory_in_hex((unsigned char*)validation_part, get_epic_header_validation_part_size(epic_header->length_of_path-1));
//    LOG_WITH_PREFIX("SEGMENT IDENTIFIERS");


    // 6. 将 hop authenticator 截断和当前的 si 进行比较
    bool equal = memory_compare(hop_authenticator, (unsigned char *) &(validation_part->validationHops[current_path_index].segment_identifier), SEGMENT_IDENTIFIER_LENGTH);
//    LOG_WITH_PREFIX("HOP_AUTHENTICATOR");
//    printk(KERN_EMERG "%s\n", key);
//    print_memory_in_hex(concatenation,  PATH_TIMESTAMP_LENGTH + HOP_IDENTIFIER_LENGTH + SEGMENT_IDENTIFIER_LENGTH);
//    print_memory_in_hex(hop_authenticator, HOP_AUTHENTICATOR_LENGTH);
//    print_memory_in_hex( (unsigned char *)&(validation_part->validationHops[current_path_index].segment_identifier), SEGMENT_IDENTIFIER_LENGTH);
//    print_memory_in_hex((unsigned char *)&(validation_part), get_epic_header_validation_part_size(epic_header->length_of_path-1));
//    LOG_WITH_PREFIX("HOP_AUTHENTICATOR");

    if(!equal){
        result = false;
        // 进行内存的释放
        kfree(hop_authenticator);
        LOG_WITH_PREFIX("hop authenticator verification failed");
        return result;
    }

    // 7. 进行接着的验证
    // ----------------------------------------------------------------------------------------------------------
    unsigned char concatenation_for_hop_validation[PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH + HOP_AUTHENTICATOR_LENGTH];
    // 7.1. 拼数据包时间戳
    memcpy(concatenation_for_hop_validation, (&validation_part->path_validation_meta.packet_timestamp), PACKET_TIMESTAMP_LENGTH);
    // 7.2. 拼源地址
    memcpy(concatenation_for_hop_validation + PACKET_TIMESTAMP_LENGTH, (&path_part->path_part_meta.src), ADDRESS_LENGTH);
    // 7.3. 拼 hop_authenticator
    memcpy(concatenation_for_hop_validation + PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH, hop_authenticator, HOP_AUTHENTICATOR_LENGTH);
    // ----------------------------------------------------------------------------------------------------------



    // 8. 进行 hop validation field 的计算
    // ----------------------------------------------------------------------------------------------------------
    char host_key[20];
    snprintf(host_key, sizeof(host_key), "key-%d-%d", pvs->node_id, epic_header->source);
    unsigned char* hop_validation_field = calculate_hmac(hmac_api,
                                                         concatenation_for_hop_validation,
                                                         PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH + HOP_AUTHENTICATOR_LENGTH,
                                                         (unsigned char*)host_key,
                                                         (int)(strlen(host_key)));
    // ----------------------------------------------------------------------------------------------------------

//    LOG_WITH_PREFIX("CONCATENATION_FOR_HOP_VALIDATION");
//    printk(KERN_EMERG "%s\n", host_key);
//    print_memory_in_hex(concatenation_for_hop_validation, PACKET_TIMESTAMP_LENGTH + ADDRESS_LENGTH + HOP_AUTHENTICATOR_LENGTH);
//    print_memory_in_hex(hop_validation_field, HOP_VALIDATION_FIELD_LENGTH * 2);
//    LOG_WITH_PREFIX("CONCATENATION_FOR_HOP_VALIDATION");

    // 9. 将计算出来的第一部分与数据包之中的内容对比
    // ----------------------------------------------------------------------------------------------------------
    equal = memory_compare(hop_validation_field,
                           (const unsigned char *) &(validation_part->validationHops[current_path_index].hop_validation_field),
                           HOP_VALIDATION_FIELD_LENGTH);

    if(!equal){
        // 将空间释放
        kfree(hop_authenticator);
        kfree(hop_validation_field);
        // 返回结果
        result = false;
        LOG_WITH_PREFIX("final verification failed");
        return result;
    }

    // 10. 进行验证字段的更新
    memcpy(&(validation_part->validationHops[current_path_index].hop_validation_field), hop_validation_field+HOP_VALIDATION_FIELD_LENGTH, HOP_VALIDATION_FIELD_LENGTH);

    // 12. 进行分配内存的释放
    kfree(hop_authenticator);
    kfree(hop_validation_field);

    // 13. 校验和会在转发之前进行更新，这里不进行更新

    return result;
}

// 目的节点的验证部分
static bool destination_proof_verification(struct EpicHeader* epic_header, struct EpicPathPart* path_part,
        struct EpicValidationPart* validation_part, struct shash_desc* hmac_api){
    // 1. 最后结果
    bool result = false;

    // 2. 获取 header 的 path_part 的大小
    int epic_hops = epic_header->length_of_path - 1;
    int path_part_size = get_epic_header_path_part_size(epic_hops);

    // 3. 计算 payload 的大小 && 找到 payload 的位置
    int payload_size = ntohs(epic_header->tot_len) - epic_header->hdr_len - sizeof(struct udphdr);
//    printk(KERN_EMERG "destination received packet payload size: %d", payload_size);
    unsigned char* payload_pointer = (unsigned char*)epic_header + get_epic_header_size(epic_hops) + sizeof(struct udphdr);


    // 4. 构建拼接
    // -------------------------------------------------------------------------------------------------------------
//    int concatenation_for_vsd_length = PACKET_TIMESTAMP_LENGTH + path_part_size + epic_hops * HOP_VALIDATION_FIELD_LENGTH + payload_size;
    int concatenation_for_vsd_length = PACKET_TIMESTAMP_LENGTH + path_part_size + epic_hops * HOP_VALIDATION_FIELD_LENGTH;
    unsigned char* concatenation_for_vsd = (unsigned char*)kmalloc(concatenation_for_vsd_length, GFP_KERNEL);

    // 4.1. 拼接 packet timestamp
    memcpy(concatenation_for_vsd, &(validation_part->path_validation_meta.packet_timestamp), PACKET_TIMESTAMP_LENGTH);

    // 4.2. 拼接 path_part
    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH, (unsigned char*)(path_part), path_part_size);

    // 4.3 拼接 validation part
    int index;
    for (index = 0; index < epic_hops; index++){
        memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + path_part_size + index * HOP_VALIDATION_FIELD_LENGTH, &(validation_part->validationHops[index].hop_validation_field), HOP_VALIDATION_FIELD_LENGTH);
    }

    // 4.3. 拼接 payload
//    memcpy(concatenation_for_vsd + PACKET_TIMESTAMP_LENGTH + path_part_size + epic_hops * HOP_VALIDATION_FIELD_LENGTH, payload_pointer, payload_size);
    // -------------------------------------------------------------------------------------------------------------

    // 5. 基于拼接进行 MAC 的计算
    char key[20];
    snprintf(key, sizeof(key), "key-%d-%d", epic_header->source, epic_header->dest);
    unsigned char* hop_validation_field = calculate_hmac(hmac_api,
                                                         concatenation_for_vsd,
                                                         PACKET_TIMESTAMP_LENGTH + path_part_size + epic_hops * HOP_VALIDATION_FIELD_LENGTH,
                                                         (unsigned char*)key,
                                                         (int)(strlen(key)));

    // 6. 将计算出来的内容与数据包之中存储的内容进行对比
    unsigned char* epic_destination_validation_start_pointer = (unsigned char *)&(validation_part->path_validation_meta.destination_validation_field);
    result = memory_compare(hop_validation_field, epic_destination_validation_start_pointer, DESTINATION_VALIDATION_LENGTH);

//    LOG_WITH_EDGE("DEST CONCATENATION_FOR_VSD");
//    print_memory_in_hex(concatenation_for_vsd, concatenation_for_vsd_length);
//    printk(KERN_EMERG "concatenation for vsd length = %d\n", concatenation_for_vsd_length);
//    LOG_WITH_EDGE("DEST CONCATENATION_FOR_VSD");


    // 7. 进行分配的内存的释放
    kfree(concatenation_for_vsd);
    kfree(hop_validation_field);


    return result;
}

int epic_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed){
    int final_result = NET_RX_DROP;
    struct EpicHeader* epic_header = epic_hdr(skb);
    // 拿到 path part
    struct EpicPathPart* path_part = get_epic_path_part_start_pointer(epic_header);
    //    LOG_WITH_EDGE("path part:");
    //    print_memory_in_hex((unsigned char*)path_part, get_epic_header_path_part_size(epic_header->length_of_path-1));
    //    LOG_WITH_EDGE("path part:");
    // 拿到 validation part
    struct EpicValidationPart* validation_part = get_epic_validation_part_start_pointer(epic_header);
    // 判断是否已经到达了目的节点
    bool is_destination = epic_header->dest == pvs->node_id;
    // 进行 hash api 和  hmac api 的初始化
    // ---------------------------------------------------------------------------------------
    // struct pv_struct p = create_pv_struct(true, true, false, NULL);
    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // ---------------------------------------------------------------------------------------

    if(is_destination){
        u64 start_verification_time = ktime_get_real_ns();
        // 进行哈希的计算和释放 (用来表示进行了 payload 的考虑)
        unsigned char* static_fields_hash = calculate_epic_hash(p->hash_api, epic_header);
        kfree(static_fields_hash);
        // 目的节点直接丢包就可以了
        bool result = destination_proof_verification(epic_header, path_part, validation_part, p->hmac_api);
        if(result){
//            printk(KERN_EMERG "destination verification succeed\n");
            final_result = NET_RX_SUCCESS;
        } else{
//            printk(KERN_EMERG "destination verification failed\n");
            final_result = NET_RX_DROP;
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
        }
        *destination_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
    } else {
        u64 start_verification_time = ktime_get_real_ns();
        // 进行哈希的计算和释放 (用来表示进行了 payload 的考虑)
        unsigned char* static_fields_hash = calculate_epic_hash(p->hash_api, epic_header);
        kfree(static_fields_hash);
        // 中间节点进行验证
        bool result = intermediate_proof_verification(epic_header, pvs, path_part, validation_part, p->hmac_api);
        *intermediate_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
        // 验证成功之后
        if(result){
            //            LOG_WITH_PREFIX("epic proof verification succeed");
            // 进行出接口的查找
            int index;
            // 拿到当前的 link_identifier (注意是根据 incoming link identifier 进行转发)
            int current_link_identifier = path_part->hop_identifiers[epic_header->current_path_index].incoming_link_id;
            // 通过 incoming_link_identifier 找到相应的接口进行转发
            struct InterfaceTableEntry* ite = NULL;
            for(index = 0; index < pvs->abit->number_of_interfaces; index++){
                struct InterfaceTableEntry* tmp = pvs->abit->interfaces[index];
                if(current_link_identifier == tmp->link_identifier){
                    ite = tmp;
                    break;
                }
            }
//            printk(KERN_EMERG "incoming link id: %d", current_link_identifier);
            if(NULL == ite){
                LOG_WITH_PREFIX("cannot find output interface");
                kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
                final_result = NET_RX_DROP;
            } else {
//                printk(KERN_EMERG "forward packets towards %s\n", ite->interface->name);
                // 11. 进行当前索引的更新
                epic_header->current_path_index += 1;
                // 转发前需要进行校验和的更新
                epic_send_check(epic_header);
                // 直接进行转发
                pv_packet_forward(skb, ite, current_ns);
                // 后续不用处理了
                final_result = NET_RX_DROP; // 不能返回 NET_RX_SUCCESS 了, 不然就要向上层递交了。
            }
        } else {
            LOG_WITH_PREFIX("epic proof verification failed");
            final_result = NET_RX_DROP;
            kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
        }

    }

    put_cpu_ptr(p);
    // free_pv_struct(&p);

    return final_result;
}