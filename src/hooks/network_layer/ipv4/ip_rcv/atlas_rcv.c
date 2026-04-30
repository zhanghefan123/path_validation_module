#include "structure/namespace/namespace.h"
#include "structure/header/atlas_header.h"
#include "structure/header/atlas_tag.h"
#include "structure/header/atlas_segment.h"
#include "structure/header/atlas_validation_field.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include <linux/inetdevice.h>
#include <linux/rhashtable.h>
#include <net/inet_ecn.h>

struct sk_buff *atlas_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct AtlasHeader *atlas_header;
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
    atlas_header = atlas_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (atlas_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, atlas_header->hdr_len))
        goto inhdr_error;

    atlas_header = atlas_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) atlas_header, atlas_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(atlas_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (atlas_header->hdr_len))
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

    atlas_header = atlas_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + atlas_header->hdr_len;

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

// free_result 进行释放
void free_result(struct Result *result){
    // 进行 validation_pointer_array 的释放
    if(result->validation_pointer_array != NULL){
        // printk(KERN_EMERG "free pointer array\n");
        kfree(result->validation_pointer_array);
    }

    // 进行 decision_pointer_array 的释放
    if(result->decision_pointer_array != NULL){
        kfree(result->decision_pointer_array);
    }

    // 进行交集的释放
    if(result->validation_segment_list != NULL) {
        // printk(KERN_EMERG "free segment list\n");
        struct AtlasSegment* entry, *tmp;
        list_for_each_entry_safe(entry, tmp, result->validation_segment_list, tmp){
            if(entry!= NULL){
                list_del(&entry->tmp);
                free_atlas_segment(entry);
            }
        }
        kfree(result->validation_segment_list);
    }

    // 进行全集的释放
    if(result->decision_segment_list != NULL){
        // printk(KERN_EMERG "free all segment list\n");
        struct AtlasSegment* entry, *tmp;
        list_for_each_entry_safe(entry, tmp, result->decision_segment_list, tmp1){
            if(entry!= NULL){
                list_del(&entry->tmp1);
                free_atlas_segment(entry);
            }
        }
        kfree(result->decision_segment_list);
    }
}

// atlas_rcv 进行接收
int atlas_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time_elapsed, u64* find_segments_time) {
    // 1. 初始化变量s
    struct net *net = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    struct AtlasHeader *atlas_header = atlas_hdr(skb);
    int process_result;

    // 2. 进行初级的(无需密码学)校验
    skb = atlas_rcv_validate(skb, net);
    if(NULL == skb){
        printk(KERN_EMERG "atlas_rcv == NULL");
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    // 3. 进行实际的(带有密码学)的校验和转发
    process_result = atlas_forward_packets(skb, pvs, net, orig_dev,  intermediate_verification_time_elapsed, destination_verification_time_elapsed, find_segments_time);

    // 4. 判断是本地交付还是直接丢弃
    if (NET_RX_SUCCESS == process_result) {
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, atlas_header->protocol,
                         receive_interface_address);
    }

    return 0;
}


// 中间节点进行校验
static bool
intermediate_verification(struct shash_desc *hmac_api, struct OptMetaData *opt_meta_data, unsigned char *pvf_location,
                          unsigned char *opv_location, int prev_node_index, char *key) {
    // 1. 进行 combination 的构建
    unsigned char combination[PVF_LENGTH + HASH_LENGTH + 4 + TIMESTAMP_LENGTH] = {0};
    memcpy(combination, pvf_location, PVF_LENGTH);
    memcpy(combination + PVF_LENGTH, &(opt_meta_data->opt_data_hash), HASH_LENGTH);
    memcpy(combination + PVF_LENGTH + HASH_LENGTH, &prev_node_index, sizeof(int));
    memcpy(combination + PVF_LENGTH + HASH_LENGTH + sizeof(int), &(opt_meta_data->timestamp), TIMESTAMP_LENGTH);
    // 2. 进行 mac 的计算
    unsigned char *calculated_opv = calculate_hmac(hmac_api,
                                                   combination,
                                                   PVF_LENGTH + HASH_LENGTH + sizeof(int) + TIMESTAMP_LENGTH,
                                                   (unsigned char *) key,
                                                   (int) strlen(key));

    // 4. 将计算结果和 opv 进行比较
    bool result =  memory_compare(opv_location, calculated_opv, OPV_LENGTH);
    kfree(calculated_opv);
    return result;
}

static void update_pvf(struct shash_desc* hmac_api, unsigned char* pvf_location, char* key){
    unsigned char* hmac_result = calculate_hmac(hmac_api,
                                                pvf_location,
                                                PVF_LENGTH,
                                                (unsigned char*)(key),
                                                (int)strlen(key));
    // 更新到 pvf 之中
    memcpy(pvf_location, hmac_result, PVF_LENGTH);

    // 进行刚创建的 pvf 的释放
    kfree(hmac_result);
}


static struct Result find_segments(struct AtlasHeader* atlas_header, unsigned char* validation_part, struct PathValidationStructure* pvs){
    // LOG_WITH_EDGE("find intersaction of segments");
    int end_tag_count = 0;
    unsigned char* current_pointer = validation_part;
    unsigned char* validation_pointer_array[100] = {NULL}; // validation pointer array (需要进行验证的 segement)
    unsigned char* decision_pointer_array[100] = {NULL}; // decison pointer array (需要进行决策的 segement)
    int validation_segment_count = 0;
    int decision_segment_count = 0;
    struct list_head* validation_segment_list = (struct list_head*)(kmalloc(sizeof(struct list_head), GFP_KERNEL));
    struct list_head* decision_segment_list = (struct list_head*)(kmalloc(sizeof(struct list_head), GFP_KERNEL));
    INIT_LIST_HEAD(validation_segment_list);
    INIT_LIST_HEAD(decision_segment_list);
    struct Result result = {};
    int total_validation_fields_count = 0;
    while (total_validation_fields_count < 1000) {
        int type_identifier = (*current_pointer);
//        int tag_id;
        if(VALIDATION_FIELD_TYPE_TAG == type_identifier){
            struct AtlasTag* atlas_tag = (struct AtlasTag*)(current_pointer);
//            tag_id = atlas_tag->index;
            if(!is_tag_removed(atlas_tag)){
                // 看是否能在已经缓存的之中找到
                struct AtlasSegment* atlasSegment = NULL;
                atlasSegment = find_atlas_segment_in_abpt(pvs->abpt, atlas_header->dest, atlas_tag->index);
                if ((NULL != atlasSegment) && (atlasSegment->decision_point != pvs->node_id)){ // 如果 self_position_in_the_segment == 0 就代表是决策节点, pvs->node_id == decison_point 也代表是决策节点
                    INIT_LIST_HEAD(&atlasSegment->tmp); // 代表的是当前的验证节点
                    list_add_tail(&atlasSegment->tmp, validation_segment_list);
                    validation_pointer_array[validation_segment_count] = current_pointer;
                    validation_segment_count++;
//                    printk(KERN_EMERG "validation segment %d\n", atlasSegment->id);
                } else if (NULL != atlasSegment && (atlasSegment->decision_point == pvs->node_id)){ // 代表的是当前的决策节点
                    INIT_LIST_HEAD(&atlasSegment->tmp1);
                    list_add_tail(&atlasSegment->tmp1, decision_segment_list);
                    decision_pointer_array[decision_segment_count] = current_pointer;
                    decision_segment_count++;
//                    printk(KERN_EMERG "decision segment %d\n", atlasSegment->id);
                } else {
//                    printk(KERN_EMERG "do not process segment %d\n", atlas_tag->index);
                }
            }
            current_pointer += ATLAS_TAG_SIZE;
            // printk(KERN_EMERG "tag\n");
        } else if(VALIDATION_FIELD_TYPE_PVF == type_identifier){
            //            if (tag_id == 1){
            //                print_memory_in_hex(current_pointer+TYPE_IDENTIFIER_LENGTH, PVF_LENGTH);
            //            }
            // printk(KERN_EMERG "pvf\n");
            current_pointer += TYPE_IDENTIFIER_LENGTH + PVF_LENGTH;
        } else if(VALIDATION_FIELD_TYPE_OPV == type_identifier){
            // print_memory_in_hex(current_pointer + TYPE_IDENTIFIER_LENGTH, OPV_LENGTH);
            current_pointer += TYPE_IDENTIFIER_LENGTH + OPV_LENGTH;
        } else if(VALIDATION_FIELD_TYPE_END_TAG == type_identifier){
            // printk(KERN_EMERG "end tag\n");
            end_tag_count+=1;
            current_pointer += ATLAS_END_TAG_SIZE;
            if(end_tag_count == atlas_header->length_of_path){
                break;
            }
        }
        total_validation_fields_count+=1;
    }
    result.validation_segment_list = validation_segment_list;
    result.decision_segment_list = decision_segment_list;
    result.validation_pointer_array = (unsigned char**)(kmalloc(sizeof(unsigned char*)*validation_segment_count, GFP_KERNEL));
    result.decision_pointer_array = (unsigned char**)(kmalloc(sizeof(unsigned char*)*decision_segment_count, GFP_KERNEL));
    memcpy(result.validation_pointer_array, validation_pointer_array, validation_segment_count*sizeof(unsigned char*));
    memcpy(result.decision_pointer_array, decision_pointer_array, decision_segment_count*sizeof(unsigned char*));
    result.validation_segment_count = validation_segment_count;
    result.decision_segment_count = decision_segment_count;
    return result;
}

// 定位 opv 的位置
static unsigned char* opv_identification(unsigned char* tag_start_pointer, struct AtlasSegment* atlas_segment){
    int count = 0;
    unsigned char* current_pointer = tag_start_pointer + ATLAS_TAG_SIZE;
    int type_identifier;
    int current_segment_id;
    int out_rotation_limit = 1000;
    int inner_rotation_limit = 1000;
    int current_rotation_outer = 0;
    while(count < atlas_segment->self_position_in_the_segment && (current_rotation_outer < out_rotation_limit)){
        type_identifier = *current_pointer;
        if(type_identifier == VALIDATION_FIELD_TYPE_PVF){
            // print_memory_in_hex(current_pointer+TYPE_IDENTIFIER_LENGTH, PVF_LENGTH);
            current_pointer += TYPE_IDENTIFIER_LENGTH + PVF_LENGTH;
        } else if(type_identifier == VALIDATION_FIELD_TYPE_OPV) {
            current_pointer += TYPE_IDENTIFIER_LENGTH;
            // ------------------------ 碰到本层的 opv 就进行递增 -------------------------
            count += 1;
            // node:3  1->2->3->10->11->12  3->4->5->10 (对于3这个节点)  position == 2 那么需要找到第一个 opv
            if(count == (atlas_segment->self_position_in_the_segment)){
                break;
            }
            current_pointer += OPV_LENGTH;
            // ------------------------ 碰到本层的 opv 就进行递增 -------------------------
        } else if(type_identifier == VALIDATION_FIELD_TYPE_TAG) {
            // ------------------------ 跳过所有的 tag id 与 end_tag id ------------------------
            // 获取当前的 tag id
            struct AtlasTag* atlas_tag = (struct AtlasTag*)(current_pointer);
            current_segment_id = atlas_tag->index;
            // 指向 pvf
            current_pointer += ATLAS_TAG_SIZE;
            int current_rotation_inner = 0;
            while (current_rotation_inner < inner_rotation_limit){
                type_identifier = *current_pointer;
                if(VALIDATION_FIELD_TYPE_PVF == type_identifier){
                    current_pointer += TYPE_IDENTIFIER_LENGTH + PVF_LENGTH;
                } else if(VALIDATION_FIELD_TYPE_OPV == type_identifier){
                    current_pointer += TYPE_IDENTIFIER_LENGTH + OPV_LENGTH;
                } else if(VALIDATION_FIELD_TYPE_END_TAG == type_identifier){
                    struct AtlasTag* atlas_end_tag = (struct AtlasTag*)(current_pointer);
                    if(atlas_end_tag->index == current_segment_id){
                        current_pointer += ATLAS_END_TAG_SIZE;
                        break;
                    }
                    current_pointer += ATLAS_END_TAG_SIZE;
                } else if(VALIDATION_FIELD_TYPE_TAG == type_identifier){
                    current_pointer += ATLAS_TAG_SIZE;
                }
                current_rotation_inner+=1;
            }
            // ------------------------ 跳过所有的 tag id 与 end_tag id ------------------------
        }
        // printk(KERN_EMERG "opv identification keep runnning\n");
        current_rotation_outer+=1;
    }
    return current_pointer;
}
// ------------------------------------------------- 校验完成 -------------------------------------------------

// 找到所有的祖先
static struct AncestorResult find_all_ancestors(struct AtlasSegment* selected_atlas_segment, struct ArrayBasedMultipathTable* abpt){
    struct AncestorResult ancestorResult = {};
    int* result = (int*)kmalloc(sizeof(int) * 100, GFP_KERNEL);
    int index = 0;
    struct AtlasSegment* son = selected_atlas_segment;
    result[index++] = selected_atlas_segment->id;
    while (true) {
        int parent_id = son->parent_id;
        struct AtlasSegment* father = find_atlas_segment_in_abpt(abpt, son->destination, parent_id);
        if (NULL == father){
            ancestorResult.ancestor_count = index;
            ancestorResult.ancestors = result;
            return ancestorResult;
        }
        if (father->depth == 0){
            break;
        } else {
            result[index++] = father->id;
            son = father;
        }

        // 找到和父亲一样的
    }

//    int count;
//    for(count = 0; count < index; count++){
//        printk(KERN_EMERG "ancesotor %d\n", result[count]);
//    }

    ancestorResult.ancestor_count = index;
    ancestorResult.ancestors = result;

    return ancestorResult;
}

// ------------------------------------------------- 校验完成 -------------------------------------------------

// 判断是否是祖先中的一个
static bool judge_is_ancestor(struct AncestorResult* ancestor_result, struct AtlasSegment* atlas_segment) {
    bool result = false;
    int index = 0;
    for(index = 0; index < ancestor_result->ancestor_count; index++){
        if(ancestor_result->ancestors[index] == atlas_segment->id){
            result = true;
            break;
        }
    }
    return result;
}

// ------------------------------------------------- 校验完成 -------------------------------------------------

// ------------------------------------------------- 校验完成 -------------------------------------------------
// 进行路径的删除
static void path_prunning(struct Result* result, struct AtlasSegment* selected_atlas_segment, struct PathValidationStructure* pvs){
//    LOG_WITH_EDGE("path prunning");
//    printk(KERN_EMERG "select segment target node id = %d", selected_atlas_segment->ite->target_node_id);
    struct list_head* position;
    // 进行所有的祖先的查找
    struct AncestorResult ancestor_result = find_all_ancestors(selected_atlas_segment, pvs->abpt);
    // 索引
    int index = 0;
    list_for_each(position, result->decision_segment_list){
        struct AtlasSegment* atlas_segment = list_entry(position, struct AtlasSegment, tmp1);
//        bool same_next_hop = (atlas_segment->array[atlas_segment->self_position_in_the_segment+1]) == selected_atlas_segment->ite->target_node_id;
        bool is_ancestor = judge_is_ancestor(&ancestor_result, atlas_segment);
        // 删除非父, 下一跳不对的, 具有相同的源的
        if((!is_ancestor)){
            traverse_and_set_to_delete(result->decision_pointer_array[index]);
        }
        index += 1;
    }

    // 进行 ancestor result 的释放
    if(ancestor_result.ancestor_count > 0){
        kfree(ancestor_result.ancestors);
    }

//    LOG_WITH_EDGE("path prunning");
}

// ------------------------------------------------- 校验完成 -------------------------------------------------

// current_pointer 指向的是 tag 开始的地方, 需要一直删除到 tag 结束的地方
void traverse_and_set_to_delete(unsigned char* current_pointer){
    struct AtlasTag* delete_start_tag = (struct AtlasTag*)(current_pointer);
    int tag_id = delete_start_tag->index;
    int rotation_limit = 1000;
    int current_rotation = 0;
    while(current_rotation  < rotation_limit){
        int type_identifier = (*current_pointer);
        if(type_identifier == VALIDATION_FIELD_TYPE_TAG) {
            struct AtlasTag* start_tag = (struct AtlasTag*)(current_pointer);
            remove_tag(start_tag);
//            printk(KERN_EMERG "node delete segment %d\n", start_tag->index);
            current_pointer += ATLAS_TAG_SIZE;
        } else if(type_identifier == VALIDATION_FIELD_TYPE_PVF){
            current_pointer += TYPE_IDENTIFIER_LENGTH + PVF_LENGTH;
        } else if (type_identifier == VALIDATION_FIELD_TYPE_OPV){
            current_pointer += TYPE_IDENTIFIER_LENGTH + OPV_LENGTH;
        } else if (type_identifier == VALIDATION_FIELD_TYPE_END_TAG) {
            struct AtlasTag* end_tag = (struct AtlasTag*)(current_pointer);
            remove_tag(end_tag);
            if(end_tag->index == tag_id){
                break;
            }
            current_pointer += ATLAS_END_TAG_SIZE;
        }
        current_rotation += 1;
    }
}

// ------------------------------------------------- 校验完成 -------------------------------------------------


// ------------------------------------------------- 校验完成 -------------------------------------------------

static struct ProofVerificationResult proof_verification(int node_id, struct OptMetaData *meta_data_part, struct Result* result, struct shash_desc* hmac_api) {
    // 0. 结果的创建
    struct ProofVerificationResult proof_verification_result = {};
    // 1. 进行所有的遍历
    struct AtlasSegment* atlas_segment;
    struct list_head* position;
    // 2. 密钥
    char key[20];
    snprintf(key, sizeof(key), "key-%d", node_id);
    // 3. 遍历
    int index = 0;
    // 4. 确定出接口
    struct AtlasSegment* selected_atlas_segment = NULL;
    // 注意当前遍历的 segment 都是本地节点并非决策节点的 segment, 并且是需要验证的 segment
    list_for_each(position, result->validation_segment_list){
        // 3.1 拿到 segment
        atlas_segment = list_entry(position, struct AtlasSegment, tmp);
        // 3.2 定位到 pvf 的位置
        unsigned char* pvf_location = result->validation_pointer_array[index] + ATLAS_TAG_SIZE + TYPE_IDENTIFIER_LENGTH;
        // 3.3 如果不是第一个节点则需要验证 OPV
        if(atlas_segment->self_position_in_the_segment != 0){
            // 前驱节点
            int previous_node = atlas_segment->array[atlas_segment->self_position_in_the_segment-1];
            // 拿到 opv 感觉中间只有可能 opv_identification 这里出现死循环
            unsigned char* opv_location = opv_identification(result->validation_pointer_array[index], atlas_segment);
            // 进行校验
            bool verification_result = intermediate_verification(hmac_api, meta_data_part, pvf_location, opv_location,
                                                                 previous_node, key);
//            printk(KERN_EMERG "destination verification\n");
            if(!verification_result){
                printk(KERN_EMERG "verification on segment %d failed !\n", atlas_segment->id);
                proof_verification_result.selected_atlas_segment = NULL;
                proof_verification_result.verification_result = false;
                return proof_verification_result;
            }
//            else {
//                printk(KERN_EMERG "verification on segment %d succeed !\n", atlas_segment->id);
//            }
        }
        // 3.4 如果不是最后一个节点则需要进行 opv 的更新
        if(atlas_segment->self_position_in_the_segment != (atlas_segment->length-1)){
            // 进行 pvf 的更新
//            printk(KERN_EMERG "update pvf for segment %d\n", atlas_segment->id);
            update_pvf(hmac_api, pvf_location, key);
        }
        // 3.5 判断当前节点不是最后一个, 也不是决策节点, 那么必然是要转发的节点
        if(atlas_segment->self_position_in_the_segment != (atlas_segment->length-1)){
            selected_atlas_segment = atlas_segment;
        }
        // 3.4 如果不是最后一个节点则需要进行 opv 的更新
        index++;
    }

//    if(NULL != selected_atlas_segment){
//        printk(KERN_EMERG "validation opv count = %d\n", result->validation_segment_count);
//    }

    proof_verification_result.selected_atlas_segment = selected_atlas_segment;
    proof_verification_result.verification_result = true;
    return proof_verification_result;
}


// ------------------------------------------------- 校验完成 -------------------------------------------------

static struct AtlasSegment* determine_output_atlas_segment(struct Result* segments_finding_result, struct PathValidationStructure* pvs){
    struct AtlasSegment* has_output_interface_segments[100];
    // 在 decision segments 之中进行随机的抽取
    //    pvs->abpt->packet_send_count += 1;
    // 选择到最后的那个节点
    struct list_head* position;
    struct AtlasSegment* selected_output_segment = NULL;
    int index = 0;
    list_for_each(position, segments_finding_result->decision_segment_list){
        struct AtlasSegment* current_segment = list_entry(position, struct AtlasSegment, tmp1);
        if (NULL != current_segment->ite){
            if(current_segment->id == 1){
                printk(KERN_EMERG "interface name: %s\n", current_segment->ite->interface->name);
            }
            has_output_interface_segments[index++] = current_segment;
        }
    }
    u32 round_robin_selection = (get_random_u32()) % (index);
    selected_output_segment = has_output_interface_segments[round_robin_selection];
    return selected_output_segment;
}

// ------------------------------------------------- 校验完成 -------------------------------------------------

// ------------------------------------------------- 校验完成 -------------------------------------------------

int atlas_forward_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                          struct net_device *in_dev, u64* intermediate_verification_time_elapsed, u64* destination_verification_time, u64* find_segments_time) {
//    printk(KERN_EMERG "node %d receive \n", pvs->node_id);

    // 最终结果
    int final_result = NET_RX_DROP;
    // 1. 获取 atlas 首部
    struct AtlasHeader *atlas_header = atlas_hdr(skb);
    // 2. 判断是否是目的节点
    bool is_destination = (pvs->node_id == atlas_header->dest);
    // 3. 拿到 meta_data_part
    struct OptMetaData *meta_data_part = (struct OptMetaData *) ((unsigned char *) (atlas_header) + sizeof(struct AtlasHeader));
    int meta_data_size = HASH_LENGTH + SESSION_ID_LENGTH + TIMESTAMP_LENGTH;
    // 4. 拿到 validation part
    unsigned char *validation_part = (unsigned char *) (meta_data_part) + meta_data_size;
    // 5. 进行 hash_api 和 hmac_api 的获取
    // ---------------------------------------------------------------------------------------
    struct pv_struct p = create_pv_struct(false, true, false, NULL);
//    struct pv_struct* p = get_cpu_ptr(&validation_api);
    // ---------------------------------------------------------------------------------------
    if(is_destination){   // 6. 如果是目的节点
//        printk(KERN_EMERG "destination receive\n");
        u64 start_verification_time = ktime_get_real_ns();
        // 6.1. 找到所有的交集合
        struct Result segments_finding_result = find_segments(atlas_header, validation_part, pvs);
        *find_segments_time = ktime_get_real_ns() - start_verification_time;
        // 6.2 如果要验证的段的数量为空, 则直接报错 (可能为 1 或者 2)
        if(segments_finding_result.validation_segment_count == 0){
            free_result(&segments_finding_result); // 释放交集查找结果
            kfree_skb(skb);
            final_result = NET_RX_DROP;
//            printk(KERN_EMERG "node %d cannot find segments\n", pvs->node_id);
        } else { // 6.3 如果要验证的段的数量不为空
//            printk(KERN_EMERG "validation_segment_count = %d\n", segments_finding_result.validation_segment_count);
            // 6.3.1 进行校验
            struct ProofVerificationResult verification_result = proof_verification(pvs->node_id, meta_data_part, &segments_finding_result, p.hmac_api);
            // 6.3.2 进行结果的释放
            free_result(&segments_finding_result);
            // 6.3.4  如果校验成功 -> 进行后续不要检查的路径的记录
            if(verification_result.verification_result){
//                printk(KERN_EMERG "destination %d verification succeed!\n", pvs->node_id);
                // 5.5 校验完成之后进行上层交付
                final_result = NET_RX_SUCCESS;
            } else {
                printk(KERN_EMERG "destination %d verification failed\n", pvs->node_id);
                // 5.6 校验失败之后直接进行数据包的释放
                kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
                final_result = NET_RX_DROP;
            }
        }
        // 释放
//        put_cpu_ptr(p);
        free_pv_struct(&p);
        *destination_verification_time = ktime_get_real_ns() - start_verification_time;
    } else { // 7. 如果不是目的节点
//        printk(KERN_EMERG "node %d receive\n",pvs->node_id);
        u64 start_verification_time = ktime_get_real_ns();
//        printk(KERN_EMERG "node %d receive\n", pvs->node_id);
        struct Result segments_finding_result = find_segments(atlas_header, validation_part, pvs);
        *find_segments_time = ktime_get_real_ns() - start_verification_time;
//        printk(KERN_EMERG "find segments\n");
        if(segments_finding_result.validation_segment_count == 0){  // 7.1.1 如果要验证的段的数量为 0
            free_result(&segments_finding_result);
            kfree_skb(skb);
            final_result = NET_RX_DROP;
            printk(KERN_EMERG "node %d cannot find segments\n", pvs->node_id);
        } else { // 7.1.2 如果要验证的段的数量不为 0
            struct ProofVerificationResult proof_verification_result;
            proof_verification_result = proof_verification(pvs->node_id, meta_data_part, &segments_finding_result, p.hmac_api);
            // 6.4 如果校验成功 -> 进行后续不要检查的路径的记录
            if(proof_verification_result.verification_result){
//                printk(KERN_EMERG "verification succeed!\n");
                // 6.4.1 进行决策
                if(segments_finding_result.decision_segment_count == 0) {
                    if(proof_verification_result.selected_atlas_segment != NULL){
                        // 根据选择的下一跳决定
                        path_prunning(&segments_finding_result, proof_verification_result.selected_atlas_segment, pvs);
                        // 6.4 进行结果的释放
                        free_result(&segments_finding_result);
                        // 6.5 进行校验
                        atlas_send_check(atlas_header);
                        // 6.6 进行数据包的转发
                        pv_packet_forward(skb, proof_verification_result.selected_atlas_segment->ite, current_ns);
                        // 6.7 设置最终的结果
                        final_result = NET_RX_DROP;
                    } else {
                        printk(KERN_EMERG "error node %d is not a decision node, and is not a node on path\n", pvs->node_id);
                        free_result(&segments_finding_result);
                        kfree_skb(skb);
                        final_result = NET_RX_DROP;
                    }
                } else { // 如果 decision segment count != 0 则 proof_verification_result.selected_atlas_segment 可能或不可能为 NULL, 都是正确的
                    // 而我们应该让节点从有出接口的之中选择一个
                    struct AtlasSegment* selected_output_segment = determine_output_atlas_segment(&segments_finding_result, pvs);
//                    printk(KERN_EMERG "selected atlas output segment = %d\n", selected_output_segment->id);
                    if (NULL == selected_output_segment) {
                        printk(KERN_EMERG "cannot find output segment\n");
                        free_result(&segments_finding_result);
                        // 6.5 进行结果的打印
                        printk(KERN_EMERG "node %d verification failed\n", pvs->node_id);
                        // 6.6 进行释放
                        kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
                        // 6.7 设置最终的结果
                        final_result = NET_RX_DROP;
                    } else {
//                        printk(KERN_EMERG "find output segment = %d parent id = %d\n", selected_output_segment->id, selected_output_segment->parent_id);
                        // 根据选择的下一跳决定
                        path_prunning(&segments_finding_result, selected_output_segment, pvs);
                        // 6.4 进行结果的释放
                        free_result(&segments_finding_result);
                        // 6.5 进行校验
                        atlas_send_check(atlas_header);
                        // 6.6 进行数据包的转发
                        pv_packet_forward(skb, selected_output_segment->ite, current_ns);
                        // 6.7 设置最终的结果
                        final_result = NET_RX_DROP;
                    }

                }
            } else {
                printk(KERN_EMERG "verification failed!\n");
                // 6.4 进行结果的释放
                free_result(&segments_finding_result);
                // 6.5 进行结果的打印
                printk(KERN_EMERG "node %d verification failed\n", pvs->node_id);
                // 6.6 进行释放
                kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
                // 6.7 设置最终的结果
                final_result = NET_RX_DROP;
            }
        }
        // 释放
        free_pv_struct(&p);
//        put_cpu_ptr(p);
        *intermediate_verification_time_elapsed = ktime_get_real_ns() - start_verification_time;
    }
    return final_result;
}

// ------------------------------------------------- 校验完成 -------------------------------------------------