#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "structure/header/fast_selir_header.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include <linux/inetdevice.h>

/**
 * 中间节点进行证明的验证
 * @param ste 会话表项
 * @param pvs 路径验证数据结构
 * @param static_fields_hash 静态字段哈希
 * @param pvf_start_pointer 数据包内的 pvf
 * @param ppf_start_pointer 数据包内的 ppf
 * @return
 */
static bool intermediate_proof_verification(struct SessionTableEntry *ste,
                                            struct PathValidationStructure *pvs,
                                            unsigned char* static_fields_hash,
                                            unsigned char* pvf_start_pointer,
                                            unsigned char* ppf_start_pointer){

    // 判断结果
    bool validation_result = false;

    // 进行布隆过滤器 bitarray 的修改
    unsigned char* original_bit_set = pvs->bloom_filter->bitset;
    pvs->bloom_filter->bitset = ppf_start_pointer;

    // 进行 pvf || hash 这个 combination 的计算
    unsigned char combination [PVF_LENGTH + HASH_OUTPUT_LENGTH] = {0};
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    memcpy(combination + PVF_LENGTH, static_fields_hash, HASH_OUTPUT_LENGTH);

    // 进行 next pvf 的计算
    unsigned char* next_pvf = calculate_hmac(pvs->hmac_api,
                                             combination,
                                             PVF_LENGTH + HASH_OUTPUT_LENGTH,
                                             ste->session_key,
                                             HMAC_OUTPUT_LENGTH);


    // 判断是否在布隆过滤器之中
    if(0 == check_element_in_bloom_filter(pvs->bloom_filter, next_pvf, 16)){
        validation_result = true;
    }

    // 进行 bitarray 的还原
    pvs->bloom_filter->bitset = original_bit_set;

    // 进行 pvf 的更新
    memcpy(pvf_start_pointer, next_pvf, PVF_LENGTH);

    // 进行 next_pvf 的释放
    kfree(next_pvf);

    return validation_result;
}

/**
 * 进行证明的校验
 * @param ste 会话表项
 * @param pvs 路径验证数据结构
 * @param pvf_start_pointer 数据包内的 pvf_start_pointer
 * @param pvf_enc_pointer 数据包内的 pvf_enc_pointer
 * @return
 */
static int destination_proof_verification(struct SessionTableEntry *ste,
                                          struct PathValidationStructure *pvs,
                                          unsigned char *pvf_start_pointer,
                                          unsigned char *pvf_enc_pointer) {
    // 1. 利用自己的会话密钥再次进行一次 MAC 计算
    unsigned char *hmac_result = calculate_hmac(pvs->hmac_api,
                                 pvf_start_pointer,
                                 PVF_LENGTH,
                                 ste->session_key,
                                 HMAC_OUTPUT_LENGTH);
    // 2. 进行两个 pvf 之间的相互的比较
    bool result = memory_compare(hmac_result, pvf_enc_pointer, PVF_LENGTH);
    // 3. 进行 hmac_result 的释放
    kfree(hmac_result);
    return result;
}

/**
 * fast_selir_rcv
 * @param skb 数据包
 * @param dev 数据包
 * @param pt 数据包类型
 * @param orig_dev 入接口
 * @return
 */
int fast_selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev){
    // 起始的时间
    u64 start = ktime_get_real_ns();
    bool if_log_time = false;
    // 1. 初始化变量
    struct net *net = dev_net(dev);
    struct FastSELiRHeader *fast_selir_header = fast_selir_hdr(skb);
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    int process_result;
    // 2. 进行初级的校验
    skb = selir_rcv_validate(skb, net);
    if (NULL == skb) {
        LOG_WITH_PREFIX("validation failed");
        return 0;
    }
    // 3. 进行实际的转发
    process_result = fast_selir_forward_packets(skb, pvs, net, orig_dev);
    // 4. 判断是否需要上层提交或者释放
    if (NET_RX_SUCCESS == process_result) {
        // 4.1 数据包向上层进行提交
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, fast_selir_header->protocol, receive_interface_address);
        if_log_time = true;

    } else {
        // 4.2 进行数据包的释放
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    }

    if(if_log_time){
        printk(KERN_EMERG "fast_selir destination forward time elapsed = %llu ns\n", ktime_get_real_ns() - start);
    }

    return 0;
}


/**
 * 进行数据包的转发
 * @param skb
 * @param pvs
 * @param current_ns
 * @param in_dev
 * @return
 */
int fast_selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev){
    // 1. 初始化变量
    int result = NET_RX_DROP;
    struct FastSELiRHeader *fast_selir_header = fast_selir_hdr(skb);
    unsigned char *pvf_start_pointer = get_fast_selir_pvf_start_pointer(fast_selir_header);
    unsigned char *pvf_enc_pointer = get_fast_selir_enc_pvf_start_pointer(fast_selir_header);
    unsigned char *ppf_start_pointer = get_fast_selir_ppf_start_pointer(fast_selir_header);
    // unsigned char *dest_pointer = get_fast_selir_dest_start_pointer(fast_selir_header, fast_selir_header->ppf_len);
    struct SessionID *session_id = (struct SessionID *) (get_fast_selir_session_id_start_pointer(fast_selir_header));

    // 2. 进行 session_table_entry 的查找
    struct SessionTableEntry *ste = find_ste_in_hbst(pvs->hbst, session_id);
    if (NULL == ste) {
        LOG_WITH_PREFIX("cannot find ste");
        return NET_RX_DROP;
    }

    bool is_destination = ste->is_destination;
    if(is_destination){
        // 5. 如果是目的节点的话进行验证
        result = destination_proof_verification(ste,
                                                pvs,
                                                pvf_start_pointer,
                                                pvf_enc_pointer);
        if(result){// 5.2 如果成功验证, 进行本地的交付
            return NET_RX_SUCCESS;
        } else {// 5.3 如果验证失败, 直接进行丢弃
            return NET_RX_DROP;
        }
    } else {
        // 6. 如果是中间节点进行哈希的计算
        unsigned char *static_fields_hash = calculate_fast_selir_hash(pvs->hash_api, fast_selir_header);
        // 进行验证
        result = intermediate_proof_verification(ste, pvs,
                                                 static_fields_hash,
                                                 pvf_start_pointer,
                                                 ppf_start_pointer);
        kfree(static_fields_hash);
        // 6.1 如果成功验证, 按照 sessionid 对应的路径进行转发
        if(result){
            // 进行重新的校验和的计算
            fast_selir_send_check(fast_selir_header);
            // 进行数据包的拷贝
            struct sk_buff *copied_skb = skb_copy(skb, GFP_KERNEL);
            // 进行数据包的转发
            pv_packet_forward(copied_skb, ste->ite, current_ns);
            return NET_RX_DROP;
        } else { // 6.2 如果验证失败, 丢弃数据包
            kfree(static_fields_hash);
            return NET_RX_DROP;
        }
    }
}