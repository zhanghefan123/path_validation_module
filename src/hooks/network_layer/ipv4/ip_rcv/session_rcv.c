#include <net/inet_ecn.h>
#include <linux/inetdevice.h>
#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/header/session_header.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

int session_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    struct net *current_ns = dev_net(dev);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 1. 初始化变量
    int process_result;
    // 2. 进行初级的校验
    skb = session_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        return 0;
    }
    process_result = forward_session_setup_packets(skb, pvs, current_ns);

    // 5. 进行数据包本地的处理 -> session packet 本就不需要进行本地交付
    if (NET_RX_DROP == process_result) {
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    }
    return 0;
}

static void destination_process_session_packets(struct PathValidationStructure *pvs, struct SessionHop *path,
                                                struct SessionID *session_id, int path_length,
                                                int current_path_index, int source) {
    // 索引
    int index;
    // 路径长度
    int encrypt_count = path_length;
    // 需要进行前驱节点的记录
    int previous_node;
    if (0 == current_path_index) {
        previous_node = source;
    } else {
        previous_node = path[current_path_index - 1].node_id;
    }

    // 计算 session_key
    char secret_value[20];
    snprintf(secret_value, sizeof(secret_value), "key-%d", pvs->node_id);
    unsigned char *session_key = calculate_hmac(pvs->hmac_api,
                                                (unsigned char *) (session_id),
                                                sizeof(struct SessionID),
                                                (unsigned char *) (secret_value),
                                                (int) (strlen(secret_value)));


    // 创建会话表项
    struct SessionTableEntry *ste = init_ste_in_dest_unicast(session_id,
                                                             encrypt_count,
                                                             previous_node,
                                                             path_length,
                                                             session_key);

    // 准备将路径拷贝到 ste->opth_ops 之中去
    memcpy(ste->session_hops, path, sizeof(struct SessionHop) * path_length);


    // 目的节点是第一个加密的, 其次是前驱节点
    ste->encrypt_order[0] = pvs->node_id;
    for (index = 0; index < path_length - 1; index++) {
        ste->encrypt_order[index + 1] = path[index].node_id;
    }

    // 按照 encrypt_order 的顺序进行 session_keys_for_opt 的计算和存储
    for (index = 0; index < path_length; index++) {
        // 从 encrypt_order 之中拿到 encrypt node
        int encrypt_node = ste->encrypt_order[index];
        // 产生 secret_value
        snprintf(secret_value, sizeof(secret_value), "key-%d", encrypt_node);
        // 计算 session_key
        unsigned char *session_key_tmp = calculate_hmac(pvs->hmac_api,
                                                        (unsigned char *) session_id,
                                                        sizeof(struct SessionID),
                                                        (unsigned char *) secret_value,
                                                        (int) (strlen(secret_value)));
        // 在 session_keys 之中进行存储
        ste->session_keys[index] = session_key_tmp;
    }

    add_entry_to_hbst(pvs->hbst, ste);
}


/**
 * 中间节点进行会话建立包的处理
 * @param skb 数据包
 * @param pvs 路径验证数据结构
 * @param session_id 会话 id
 * @param path 路径
 * @param opt_header opt 头部
 * @param current_ns 当前的网络命名孔金啊
 * @param current_link_identifier 当前的 link_identifier
 * @param current_path_index 当前的路径索引
 * @param source 源
 */
static void intermediate_process_session_packets(struct sk_buff *skb,
                                                 struct PathValidationStructure *pvs,
                                                 struct SessionID *session_id,
                                                 struct SessionHop *path,
                                                 struct SessionHeader *session_header,
                                                 struct net *current_ns,
                                                 int current_link_identifier,
                                                 int current_path_index,
                                                 int source) {
    int index;
    // 等待被填充的出接口
    struct InterfaceTableEntry *ite = NULL;
    // 进行转发方向的决定
    for (index = 0; index < pvs->abit->number_of_interfaces; index++) {
        struct InterfaceTableEntry *ite_tmp = pvs->abit->interfaces[index];
        if (current_link_identifier == ite_tmp->link_identifier) {
            ite = ite_tmp;
            break;
        }
    }
    // 需要进行前驱节点的记录
    int previous_node;
    if (0 == current_path_index) {
        previous_node = source;
    } else {
        previous_node = path[current_path_index - 1].node_id;
    }
    // 依据 session_id 以及 secret_value 进行 session_key 的计算
    char secret_value[20];
    snprintf(secret_value, sizeof(secret_value), "key-%d", pvs->node_id);
    unsigned char *session_key = calculate_hmac(pvs->hmac_api,
                                                (unsigned char *) (session_id),
                                                sizeof(struct SessionID),
                                                (unsigned char *) (secret_value),
                                                (int) (strlen(secret_value)));
    // 创建会话表项目
    struct SessionTableEntry *ste = init_ste_in_intermediate_unicast(session_id, ite, session_key, previous_node);
    // 将会话表项添加到 hbst 之中
    add_entry_to_hbst(pvs->hbst, ste);
    // 进行 current_path_index 的更新
    session_header->current_path_index += 1;
    // 在更新完了 current_path_index 之后一定需要进行 check 的更新
    session_setup_send_check(session_header);
    // 进行数据包的转发
    if (NULL != ite->interface) {
        pv_packet_forward(skb, ite, current_ns);
    }
}

int forward_session_setup_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net* current_ns) {
    // 1. 拿到首部
    struct SessionHeader *session_header = session_hdr(skb);
    // 2. 拿到路径长度
    int path_length = session_header->path_length;
    // 3. 拿到规划的路径
    struct SessionHop *path = (struct SessionHop *) (get_session_setup_schedule_path_start_pointer(session_header));
    // 4. 拿到 session_id
    struct SessionID *session_id = (struct SessionID *) (get_session_setup_session_id_pointer(session_header));
    // 5. 拿到当前的索引
    int current_index = session_header->current_path_index;
    // 6. 源节点
    int source = session_header->source;
    // 7. 目的节点
    int destination = session_header->dest;
    // 8. 拿到当前的 link identifier
    int current_link_identifier = path[current_index].link_id;
    // 9. 拿到当前的 id
    int current_node_id = pvs->node_id;
    if (current_node_id == destination) {
        destination_process_session_packets(pvs, path, session_id, path_length, current_index, source);
        return NET_RX_DROP;
    } else {
        intermediate_process_session_packets(skb, pvs, session_id, path, session_header, current_ns,
                                             current_link_identifier, current_index, source);
        return NET_RX_NOTHING;
    }
}


struct sk_buff *session_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct SessionHeader *session_header;
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
    session_header = session_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (session_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, session_header->hdr_len))
        goto inhdr_error;

    session_header = session_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) session_header, session_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(session_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (session_header->hdr_len))
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

    session_header = session_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + session_header->hdr_len;

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