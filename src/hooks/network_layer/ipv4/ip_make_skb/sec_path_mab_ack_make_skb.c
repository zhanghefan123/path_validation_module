#include "structure/header/sec_path_mab_header.h"
#include "structure/header/sec_path_mab_ack_header.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "api/test.h"
#include <linux/inetdevice.h>


/**
 * 将 ack skb 之中的路径部分进行设置 (S->A->B->C->D) 当到达 B 节点的时候 current_path_index = 1, 正好进行索引 1 和 0 的遍历
 * @param sec_path_mab_ack_header
 * @param old_header
 */
static void set_sec_path_mab_ack_skb_path_part(struct SecPathMabHopIdentifier *new_hop_identifiers,
                                               struct SecPathMabHeader *old_header) {
    if(NULL != new_hop_identifiers){
        // 1. 获取路径的旧的部分
        struct SecPathMabPathPart *old_path_part = get_sec_path_mab_path_part(old_header);
        // 2. 将 hop identifiers 进行反转
        int index;
        int count = 0;
        for (index = (old_header->current_path_index - 1); index >= 0; index--) {
            struct SecPathMabHopIdentifier* temp = &(new_hop_identifiers[count++]);
            temp->link_id = old_path_part->hop_identifiers[index].incoming_link_id;
            temp->incoming_link_id = -1;
        }
    }
}

/**
 * 进行 ack 的构造
 * @param old_skb
 * @param ack_content
 * @param ite
 * @return
 */
struct sk_buff *
self_defined_make_sec_path_mab_ack_skb(struct sk_buff *old_skb, void *ack_content, struct InterfaceTableEntry *ite, int current_path_index) {
    // extract old header
    struct SecPathMabHeader *old_header = sec_path_mab_hdr(old_skb);
    // ack length (S->A->B->C->D) 之中 B 返回时的 path_length == 1 == current_path_index (S->D 的长度为 5 实际上 path_length == 3)
    int ack_header_size = get_sec_path_mab_ack_header_size(current_path_index);
    // alloc new skb
    struct sk_buff *new_skb = alloc_skb(ack_header_size + LL_RESERVED_SPACE(ite->interface), GFP_ATOMIC);
    if (!new_skb) {
        printk(KERN_EMERG "create ack packet skb failed\n");
        return NULL;
    }
    // memory prepare for mac (data 和 tail + 指定长度, head 不变)
    skb_reserve(new_skb, LL_RESERVED_SPACE(ite->interface));
    // fix ip header position
    skb_reset_network_header(new_skb);
    // put ack content

    // push data between data and tail
    // -----------------------------------------------------------------------------------------------------------------------
    struct SecPathMabAckHeader *new_header = (struct SecPathMabAckHeader *) skb_put(new_skb,sizeof(struct SecPathMabAckHeader));
    struct SecPathMabHopIdentifier* hop_identifiers = NULL;
    if(current_path_index > 0){
        hop_identifiers = (struct SecPathMabHopIdentifier*) skb_put(new_skb, sizeof(struct SecPathMabHopIdentifier) * current_path_index);
    }
    skb_put_data(new_skb, ack_content, ACK_AUTHENTICATION_LENGTH);
    // -----------------------------------------------------------------------------------------------------------------------

    // set header fields
    // -----------------------------------------------------------------------------------------------------------------------
    new_header->version = SEC_PATH_MAB_ACK_VERSION_NUMBER; // 版本 (字段1)
    new_header->identifier = old_header->identifier; // identifier (字段1)
    new_header->epoch = old_header->epoch; // epoch (字段2)
    new_header->tos = old_header->tos; // tos type_of_service (字段2)
    new_header->ttl = 64; // ttl (字段3)
    new_header->protocol = old_header->protocol; // 上层协议 (字段4)
    new_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    new_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    new_header->check = 0; // 校验和字段 (字段7)
    new_header->source = ite->interface->ip_ptr->ifa_list->ifa_address;; // 设置源 (字段8)
    new_header->dest = old_header->source; // 设置目的 (字段9)
    new_header->hdr_len = ack_header_size; // 设置数据包总长度 (字段10)
    new_header->tot_len = htons(new_skb->len);// tot_len 字段 11 (等待后面进行赋值)
    new_header->length_of_path = current_path_index;
    new_header->current_path_index = 0;
    // -----------------------------------------------------------------------------------------------------------------------

    // set the path part
    // -----------------------------------------------------------------------------------------------------------------------
    set_sec_path_mab_ack_skb_path_part(hop_identifiers, old_header);
    // -----------------------------------------------------------------------------------------------------------------------

    // print the ack content
    //    printk(KERN_EMERG "--------------------- ACK CONTENT ---------------------\n");
    //    print_memory_in_hex((unsigned char*)(get_sec_path_mab_ack_validation_part(new_header)), ACK_AUTHENTICATION_LENGTH);
    //    printk(KERN_EMERG "--------------------- ACK CONTENT ---------------------\n");

    // calculate checksum
    // -----------------------------------------------------------------------------------------------------------------------
    sec_path_mab_ack_send_check(new_header);
    // -----------------------------------------------------------------------------------------------------------------------

    // forward the packet
    return new_skb;
}