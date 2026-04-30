#include "api/netlink_router.h"
#include "api/netlink_handler.h"
#include "structure/path_validation_structure.h"
#include "structure/namespace/namespace.h"
#include "structure/routing/routing_table_entry.h"
#include "structure/routing/variables.h"
#include "structure/routing/array_based_multipath_table.h"
#include "structure/header/atlas_segment.h"
#include "structure/routing/sec_path_mab_route.h"
#include "structure/routing/table_common.h"
#include "types/router_types.h"
#include "types/sec_path_mab_types.h"
#include <linux/inet.h>
#include <linux/list.h>

/**
 * netlink_handler.c - 路径验证模块的 Generic Netlink 命令处理
 *
 * 用户态通过属性 EXMPL_NLA_DATA 下发以 '\\0' 结尾的字符串；本文件解析后更新当前网络命名空间内的
 * PathValidationStructure 及相关表项。常见格式为单个十进制整数或逗号分隔的整数列表。
 *
 * 返回值约定：成功返回 0；失败返回负数 errno（如 -EINVAL、-ENOMEM），与 recv_message_copy()、
 * send_reply() 等辅助函数一致。
 */

/** 为 true 时表示已为每个 possible CPU 分配过布隆过滤器（全局一次，非按 netns）。 */
static bool per_cpu_bloom_fitler_initialized = false;

/**
 * recv_message_copy() - 将 EXMPL_NLA_DATA 载荷拷贝到可写缓冲区
 * @info: genl 回调传入的 genl_info
 * @buffer: 输出缓冲区（须非 NULL，且容量为 buffer_size 字节）
 * @buffer_size: buffer 字节长度（须能容纳载荷及结尾 '\\0'）
 *
 * Return: 成功为 0；info/属性无效或 len >= buffer_size 时为 -EINVAL（并在 buffer 可用时置 buffer[0]='\\0'）。
 */
int recv_message_copy(struct genl_info *info, char *buffer, size_t buffer_size) {
    const char *src;
    size_t len;

    if (NULL == info) {
        buffer[0] = '\0';
        return -EINVAL;
    }
    if (!info->attrs[EXMPL_NLA_DATA]) {
        buffer[0] = '\0';
        return -EINVAL;
    }
    src = nla_data(info->attrs[EXMPL_NLA_DATA]);
    len = nla_len(info->attrs[EXMPL_NLA_DATA]);

    if (len >= buffer_size) {
        buffer[0] = '\0';
        return -EINVAL;
    }

    memcpy(buffer, src, len);
    buffer[len] = '\0';

    return 0;
}

/**
 * recv_message() - 返回 EXMPL_NLA_DATA 在内核 skb 中的指针（零拷贝）
 * @info: genl 回调传入的 genl_info
 *
 * 返回指向 netlink 属性数据的指针，生命周期随 skb；info 无效或缺少属性时返回空字符串字面量。
 * 若需长期保存或修改内容，应使用 recv_message_copy()。
 */
char *recv_message(struct genl_info *info) {
    if (NULL == info) {
        return "";
    }
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return "";
    }
    return nla_data(info->attrs[EXMPL_NLA_DATA]);
}

/**
 * send_reply() - 构造并向发起方回复一条 genl 消息
 * @response_buffer: 回复中的字符串内容（写入 EXMPL_NLA_DATA），可为空串
 * @info: genl 回调传入的 genl_info（用于 genlmsg_reply）
 *
 * 回复属性：EXMPL_NLA_DATA 为字符串；EXMPL_NLA_LEN 为 nla_put_u32，值为 strlen(response_buffer)。
 *
 * Return: 成功为 0；分配或封装失败为 -ENOMEM/-EINVAL。
 */
int send_reply(char *response_buffer, struct genl_info *info) {
    struct sk_buff *reply_message;
    void *message_header;

    reply_message = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (NULL == reply_message) {
        return -ENOMEM;
    }
    message_header = genlmsg_put_reply(reply_message, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (NULL == message_header) {
        kfree_skb(reply_message);
        return -ENOMEM;
    }
    if (0 != nla_put_string(reply_message, EXMPL_NLA_DATA, response_buffer)) {
        kfree_skb(reply_message);
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply_message, EXMPL_NLA_LEN, strlen(response_buffer))) {
        kfree_skb(reply_message);
        return -EINVAL;
    }
    genlmsg_end(reply_message, message_header);
    if (0 != genlmsg_reply(reply_message, info)) {
        return -EINVAL;
    }
    return 0;
}

/**
 * netlink_echo_handler() - CMD_ECHO：回显用户态载荷
 * @request: 请求 skb（本处理未使用）
 * @info: genl 属性，载荷经 EXMPL_NLA_DATA 下发
 *
 * Return: 0 或 send_reply()/recv_message_copy() 的错误码。
 */
int netlink_echo_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    if (0 == strcmp("", receive_buffer)) {
        return -EINVAL;
    }
    snprintf(response_buffer, sizeof(response_buffer), "CMD ECHO: %s", receive_buffer);
    return send_reply(response_buffer, info);
}

/**
 * netlink_set_node_id_handler() - 设置当前命名空间节点的 node_id
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：十进制整数字符串，表示本节点 ID。
 *
 * Return: 0 或负数错误码。
 */
int netlink_set_node_id_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    int node_id;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    node_id = (int) (simple_strtol(receive_buffer, NULL, 10));
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    pvs->node_id = node_id;
    snprintf(response_buffer, sizeof(response_buffer), "CMD_SET_NODE_ID: node id: %d", node_id);
    return send_reply(response_buffer, info);
}

/**
 * netlink_init_array_based_multipath_table_handler() - 初始化基于数组的多路径表（ABPT）
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：逗号分隔的 5 个整数 —
 * multipath_routing_type, number_of_buckets, number_of_destinations,
 * number_of_relationships, number_of_paths。
 *
 * Return: 0 或负数错误码。
 */
int netlink_init_array_based_multipath_table_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimiter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    int multipath_routing_type;
    int number_of_buckets;
    int number_of_destinations;
    int number_of_relationships;
    int number_of_paths;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                multipath_routing_type = variable_in_integer;
            } else if (count == 1) {
                number_of_buckets = variable_in_integer;
            } else if (count == 2) {
                number_of_destinations = variable_in_integer;
            } else if (count == 3) {
                number_of_relationships = variable_in_integer;
            } else if (count == 4) {
                number_of_paths = variable_in_integer;
            } else {
                printk(KERN_EMERG "there are more than five params in CMD_INIT_MULTIPATH_TABLE");
                return -EINVAL;
            }
        }
        count += 1;
    }
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    initialize_multipath_table(pvs, multipath_routing_type, number_of_buckets, number_of_destinations,
                               number_of_relationships, number_of_paths);
    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INIT_MULTIPATH_TABLE: multipath_routing_type: %d | number_of_buckets: %d | number_of_destinations: %d | number_of_relations: %d | number_of_paths: %d",
             multipath_routing_type, number_of_buckets, number_of_destinations, number_of_relationships,
             number_of_paths);
    return send_reply(response_buffer, info);
}

/**
 * netlink_init_routing_table() - 初始化路由表（数组或哈希）
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：逗号分隔的两个整数 — routing_table_type, number_of_routes_or_buckets
 *（数组表为路由条数，哈希表为桶数）。
 *
 * Return: 0 或负数错误码。
 */
int netlink_init_routing_table(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimiter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    int routing_table_type;
    int number_of_routes_or_buckets;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                routing_table_type = variable_in_integer;
            } else if (count == 1) {
                number_of_routes_or_buckets = variable_in_integer;
            } else {
                printk(KERN_EMERG "there are more than three params in CMD_INIT_ROUTING_TABLE");
                return -EINVAL;
            }
        }
        count += 1;
    }
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    initialize_routing_table(pvs,
                             routing_table_type,
                             number_of_routes_or_buckets);
    if (routing_table_type == ARRAY_BASED_ROUTING_TABLE_TYPE) {
        snprintf(response_buffer, sizeof(response_buffer),
                 "CMD_INIT_ROUTING_TABLE: routing table type: %d | number_of_routes: %d",
                 routing_table_type, number_of_routes_or_buckets);
    } else if (routing_table_type == HASH_BASED_ROUTING_TABLE_TYPE) {
        snprintf(response_buffer, sizeof(response_buffer),
                 "CMD_INIT_ROUTING_TABLE: routing table type: %d | number_of_buckets: %d",
                 routing_table_type, number_of_routes_or_buckets);
    } else {
        snprintf(response_buffer, sizeof(response_buffer), "CMD_INIT_ROUTING_TABLE: unknown routing table type");
    }
    return send_reply(response_buffer, info);
}

/**
 * netlink_init_interface_table() - 初始化接口/转发表容量
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：单个十进制整数 number_of_interfaces。
 *
 * Return: 0 或负数错误码。
 */
int netlink_init_interface_table(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimiter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    int number_of_interfaces;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                number_of_interfaces = variable_in_integer;
            } else {
                printk(KERN_EMERG "there are more than one param in CMD_INIT_FORWARDING_TABLE");
                return -EINVAL;
            }
        }
        count += 1;
    }
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    initialize_forwarding_table(pvs, number_of_interfaces);
    snprintf(response_buffer, sizeof(response_buffer), "CMD_INIT_INTERFACE_TABLE: number_of_interfaces: %d",
             number_of_interfaces);
    return send_reply(response_buffer, info);
}


/**
 * netlink_init_selir() - 配置 SelIR 的 PVF 有效位宽
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：单个十进制整数 pvf_effective_bits（单位：bit）。
 *
 * Return: 0 或负数错误码。
 */
int netlink_init_selir(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimiter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    int pvf_effective_bits;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                pvf_effective_bits = variable_in_integer;
            } else {
                printk(KERN_EMERG "there are more than one param in CMD_INIT_SELIR");
                return -EINVAL;
            }
        }
        count += 1;
    }
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if (NULL == pvs) {
        return -EINVAL;
    }

    pvs->selir_info->pvf_effective_bits = pvf_effective_bits;
    pvs->selir_info->pvf_effective_bytes = (pvf_effective_bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD INIT SELIR: selir pvf_effective_bits: %d, pvf_effective_bytes: %d",
             pvs->selir_info->pvf_effective_bits,
             pvs->selir_info->pvf_effective_bytes);
    return send_reply(response_buffer, info);
}

/**
 * netlink_init_bloom_filter_handler() - 创建并挂接命名空间布隆过滤器，并可选初始化每 CPU 副本
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：逗号分隔的三个整数 — bf_effective_bits, hash_seed, number_of_hash_functions。
 *
 * Return: 0 或负数错误码。
 */
int netlink_init_bloom_filter_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimeter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    int bf_effective_bits;
    int hash_seed;
    int number_of_hash_functions;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                bf_effective_bits = variable_in_integer;
            } else if (count == 1) {
                hash_seed = variable_in_integer;
            } else if (count == 2) {
                number_of_hash_functions = variable_in_integer;
            } else {
                printk(KERN_EMERG "there are more than four param in CMD_INIT_BLOOM_FILTER");
                return -EINVAL;
            }
        }
        count += 1;
    }
    struct BloomFilter *bloom_filter = init_bloom_filter(bf_effective_bits,
                                                         hash_seed,
                                                         number_of_hash_functions);
    reset_bloom_filter(bloom_filter);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if (NULL == pvs) {
        return -EINVAL;
    } else {
        pvs->bloom_filter = bloom_filter;
    }

    if (!per_cpu_bloom_fitler_initialized) {
        int cpu;
        for_each_possible_cpu(cpu) {
            struct pv_struct *pv = per_cpu_ptr(&validation_api, cpu);
            pv->bloom_filter = init_bloom_filter(bf_effective_bits, hash_seed, number_of_hash_functions);
        }
        per_cpu_bloom_fitler_initialized = true;
    }

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INIT_BLOOM_FILTER: effective_bits: %d, hash_seed: %d, number_of_hash_functions: %d",
             bf_effective_bits, hash_seed, number_of_hash_functions);
    return send_reply(response_buffer, info);
}

/**
 * netlink_modify_bloom_filter_handler() - 修改布隆过滤器位宽并重建每 CPU 实例
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：单个十进制整数 bf_effective_bits。
 *
 * Return: 0 或负数错误码。
 */
int netlink_modify_bloom_filter_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int bf_effective_bits;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    bf_effective_bits = (int) (simple_strtol(receive_buffer, NULL, 10));

    pvs->bloom_filter->bf_effective_bits = bf_effective_bits;
    pvs->bloom_filter->bf_effective_bytes = (bf_effective_bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;

    int cpu;
    for_each_possible_cpu(cpu) {
        struct pv_struct *p = per_cpu_ptr(&validation_api, cpu);
        delete_bloom_filter(p->bloom_filter);
        p->bloom_filter = init_bloom_filter(pvs->bloom_filter->bf_effective_bits,
                                            pvs->bloom_filter->hash_seed,
                                            pvs->bloom_filter->number_of_hash_functions);
    }

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_MODIFY_BLOOM_FILTER: already modify bloom filter bits to %d\n", bf_effective_bits);
    return send_reply(response_buffer, info);
}

/**
 * netlink_clear_segment_list() - 按目的节点清空 ABPT 上的 segment/path 链表
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：十进制 destination。支持 ATLAS 与 MULTIPATH_SELIR 路由类型。
 *
 * Return: 0 或负数错误码。
 */
int netlink_clear_segment_list(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int destination;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    destination = (int) (simple_strtol(receive_buffer, NULL, 10));

    if (NULL != pvs->abpt) {
        struct list_head *segments_or_paths = find_segments_or_paths_in_abpt(pvs->abpt, destination);
        if (pvs->abpt->routing_type == ROUTING_TYPE_ATLAS) {
            delete_segment_list(segments_or_paths);
        } else if (pvs->abpt->routing_type == ROUTING_TYPE_MULTIPATH_SELIR) {
            delete_paths_list(segments_or_paths);
        } else {
            printk(KERN_EMERG "unsupported multipath routing type %d", pvs->abpt->routing_type);
        }
    } else {
        printk(KERN_EMERG "abpt == NULL\n");
    }

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_CLEAR_SEGMENT: already delete segment list");
    return send_reply(response_buffer, info);
}

/**
 * netlink_insert_output_link_identifiers() - 为某目的写入输出链路标识列表
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：逗号分隔，首字段为 destination，其次为数量 N，随后 N 个 link identifier。
 *
 * Return: 0 或负数错误码。
 */
int netlink_insert_output_link_identifiers(struct sk_buff *request, struct genl_info *info) {
    const char *delimiter = ",";
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int count = 0;
    struct OutputLinkIdentifiers *output_link_identifier;

    int destination;
    int link_identifiers_count;
    int link_identifier;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            if (count == 0) {
                destination = (int) (simple_strtol(variable_in_str, NULL, 10));
                output_link_identifier = &(pvs->abpt->output_link_identifiers[destination]);
            } else if (count == 1) {
                link_identifiers_count = (int) (simple_strtol(variable_in_str, NULL, 10));
                output_link_identifier->number = link_identifiers_count;
                output_link_identifier->link_identifiers = (int *) kmalloc(sizeof(int) * link_identifiers_count,
                                                                           GFP_ATOMIC);
            } else {
                link_identifier = (int) (simple_strtol(variable_in_str, NULL, 10));
                output_link_identifier->link_identifiers[count - 2] = link_identifier;
            }
        }
        count += 1;
    }

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INSERT_OUTPUT_LINK_IDENTIFIERS: destination: %d | link_identifiers count: %d", destination,
             link_identifiers_count);
    return send_reply(response_buffer, info);
}

/**
 * netlink_insert_relationship_between_next_node_id_and_paths() - 登记「下一跳节点 → 路径集合」映射
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 在解析载荷前会占用 abpt 中下一槽位并递增 interface_to_path_mapping_index。
 * 载荷（逗号分隔）：current_node_id, target_node_id, path 条数 M, 随后 M 个 path_id。
 * target_node_id 用于在接口表中查找出接口；path_id 同时写入 path_ids 与 bit_set。
 *
 * Return: 0 或负数错误码。
 */
int netlink_insert_relationship_between_next_node_id_and_paths(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr = receive_buffer;
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    const char *delimeter = ",";
    int count = 0;
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int current_node_id;
    int target_node_id;
    int segments_count;
    int path_id;

    pvs->abpt->output_interface_to_path_mappings[pvs->abpt->interface_to_path_mapping_index] = (struct OutputInterfaceToPathsMapping *) (kmalloc(
            sizeof(struct OutputInterfaceToPathsMapping), GFP_ATOMIC));

    struct OutputInterfaceToPathsMapping *output_interface_to_segment_mapping = pvs->abpt->output_interface_to_path_mappings[pvs->abpt->interface_to_path_mapping_index];

    pvs->abpt->interface_to_path_mapping_index += 1;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                current_node_id = variable_in_integer;
            } else if (count == 1) {
                target_node_id = variable_in_integer;
                int index;
                struct InterfaceTableEntry *ite = NULL;
                for (index = 0; index < pvs->abit->number_of_interfaces; index++) {
                    struct InterfaceTableEntry *tmp = pvs->abit->interfaces[index];
                    if (tmp->target_node_id == target_node_id) {
                        ite = tmp;
                        break;
                    }
                }
                if (ite == NULL) {
                    printk(KERN_EMERG "ite == NULL\n");
                } else {
                    printk(KERN_EMERG "output interface name = %s\n", ite->interface->name);
                }
                output_interface_to_segment_mapping->ite = ite;
            } else if (count == 2) {
                segments_count = variable_in_integer;
                output_interface_to_segment_mapping->path_ids_count = segments_count;
                output_interface_to_segment_mapping->path_ids = (unsigned char *) (kmalloc(
                        sizeof(unsigned char) * segments_count, GFP_ATOMIC));

                int size = DIV_ROUND_UP(pvs->abpt->number_of_paths, 8);
                printk(KERN_EMERG "node id %d | bit set size %d\n", pvs->node_id, size);
                output_interface_to_segment_mapping->bit_set = (unsigned char *) (kmalloc(sizeof(unsigned char) * size,
                                                                                          GFP_ATOMIC));
                memset(output_interface_to_segment_mapping->bit_set, 0, size);
            } else {
                path_id = variable_in_integer;
                output_interface_to_segment_mapping->path_ids[count - 3] = path_id;
                set_bit(path_id - 1, (unsigned long *) (output_interface_to_segment_mapping->bit_set));
            }
        }
        count += 1;
    }

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INSERT_RELATIONSHIP_BETWEEN_NEXT_NODE_ID_AND_PATHS: node %d add mapping with segments length = %d",
             pvs->node_id, output_interface_to_segment_mapping->path_ids_count);
    return send_reply(response_buffer, info);
}


/**
 * netlink_source_insert_segment_handler() - ATLAS：源节点按载荷插入 segment
 * @request: 请求 skb
 * @info: genl 属性，整段字符串交由 source_insert_atlas_segment() 解析
 *
 * Return: 0 或负数错误码。
 */
int netlink_source_insert_segment_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    struct AtlasSegment *atlas_segment = source_insert_atlas_segment(receive_buffer, pvs->abpt);

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_SOURCE_INSERT_SEGMENT: source add segment with length = %d", atlas_segment->length);
    return send_reply(response_buffer, info);
}

/**
 * netlink_intermediate_insert_segment_handler() - ATLAS：中间节点按载荷插入 segment
 * @request: 请求 skb
 * @info: genl 属性
 *
 * Return: 0 或负数错误码。
 */
int netlink_intermediate_insert_segment_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    struct AtlasSegment *atlas_segment = intermediate_insert_atlas_segment(receive_buffer, pvs->abpt);

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INTERMEDIATE_INSERT_SEGMENT: intermediate add segment with length = %d", atlas_segment->length);
    return send_reply(response_buffer, info);
}

/**
 * netlink_insert_routing_table_entry_handler() - 插入一条路由表项（数组/哈希/多路径链式表）
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷（逗号分隔）：source_id, destination_id, path_length=L，
 * 随后交替 L 组 link_id 与 node_id；首条 link_id 用于解析出接口且不进入布隆过滤器，
 * 其余 link_id 依次压入临时布隆过滤器，最后拷贝 bitset 到 rte 并重置全局 bf。
 *
 * 示例拓扑 a -1-> b -2-> c：链路 [1,2]，中间节点 [b,c] 对应字段顺序见实现中的 count 分支。
 *
 * Return: 0 或负数错误码。
 */
int netlink_insert_routing_table_entry_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimeter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    struct BloomFilter *bf = pvs->bloom_filter;
    struct RoutingTableEntry *rte = init_routing_table_entry((int) (bf->bf_effective_bytes));
    struct InterfaceTableEntry *first_interface = NULL;
    int source_id;
    int destination_id;
    int path_length;
    int first_link_identifier;
    int link_identifier_index = 0;
    int node_index = 0;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                source_id = variable_in_integer;
                rte->source_id = source_id;
            } else if (count == 1) {
                destination_id = variable_in_integer;
                rte->destination_id = destination_id;
            } else if (count == 2) {
                path_length = variable_in_integer;
                rte->path_length = path_length;
                rte->link_identifiers = (int *) kmalloc(sizeof(int) * path_length, GFP_ATOMIC);
                rte->node_ids = (int *) kmalloc(sizeof(int) * path_length, GFP_ATOMIC);
            } else {
                if (count == 3) {
                    printk(KERN_EMERG "current node id: %d source: %d target: %d link_identifier: %d \n", pvs->node_id,
                           source_id, destination_id, variable_in_integer);
                    first_link_identifier = variable_in_integer;
                    first_interface = find_ite_in_abit_with_link_identifier(pvs->abit, first_link_identifier);
                    rte->output_interface = first_interface;
                    rte->link_identifiers[link_identifier_index++] = variable_in_integer;
                    /* 首跳 link id 仅用于匹配出接口，不写入布隆过滤器 */
                } else if (count % 2 == 0) {
                    rte->node_ids[node_index++] = variable_in_integer;
                } else if (count % 2 == 1) {
                    rte->link_identifiers[link_identifier_index++] = variable_in_integer;
                    push_element_into_bloom_filter(bf, &variable_in_integer, sizeof(variable_in_integer));
                }
            }
        }
        count += 1;
    }
    memcpy(rte->bitset, bf->bitset, sizeof(unsigned char) * bf->bf_effective_bytes);
    reset_bloom_filter(bf);
    if (ARRAY_BASED_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        add_entry_to_abrt(pvs->abrt, rte);
    } else if (HASH_BASED_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        add_entry_to_hbrt(pvs->hbrt, rte);
    } else if (MULTIPATH_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        add_routing_table_entry_to_abpt_in_chain_format(pvs->abpt, rte);
    } else {
        printk(KERN_EMERG "unsupported routing table version number");
    }
    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INSERT_ROUTING_TABLE_ENTRY: source_id: %d, destination_id: %d, path_length: %d, link_identifier_index: %d, node_index: %d",
             source_id, destination_id, path_length, link_identifier_index, node_index);
    return send_reply(response_buffer, info);
}

/**
 * netlink_insert_dest_routing_table_entry_handler() - 以哈希格式向多路径表插入路由项
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷格式与 netlink_insert_routing_table_entry_handler() 相同；仅当 routing_table_type 为
 * MULTIPATH_ROUTING_TABLE_TYPE 时写入 abpt（哈希布局），否则打印不支持类型。
 *
 * Return: 0 或负数错误码。
 */
int netlink_insert_dest_routing_table_entry_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimeter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    struct BloomFilter *bf = pvs->bloom_filter;
    struct RoutingTableEntry *rte = init_routing_table_entry((int) (bf->bf_effective_bytes));
    struct InterfaceTableEntry *first_interface = NULL;
    int source_id;
    int destination_id;
    int path_length;
    int first_link_identifier;
    int link_identifier_index = 0;
    int node_index = 0;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                source_id = variable_in_integer;
                rte->source_id = source_id;
            } else if (count == 1) {
                destination_id = variable_in_integer;
                rte->destination_id = destination_id;
            } else if (count == 2) {
                path_length = variable_in_integer;
                rte->path_length = path_length;
                rte->link_identifiers = (int *) kmalloc(sizeof(int) * path_length, GFP_ATOMIC);
                rte->node_ids = (int *) kmalloc(sizeof(int) * path_length, GFP_ATOMIC);
            } else {
                if (count == 3) {
                    printk(KERN_EMERG "current node id: %d source: %d target: %d link_identifier: %d \n", pvs->node_id,
                           source_id, destination_id, variable_in_integer);
                    first_link_identifier = variable_in_integer;
                    first_interface = find_ite_in_abit_with_link_identifier(pvs->abit, first_link_identifier);
                    rte->output_interface = first_interface;
                    rte->link_identifiers[link_identifier_index++] = variable_in_integer;
                    /* 首跳 link id 仅用于匹配出接口，不写入布隆过滤器 */
                } else if (count % 2 == 0) {
                    rte->node_ids[node_index++] = variable_in_integer;
                } else if (count % 2 == 1) {
                    rte->link_identifiers[link_identifier_index++] = variable_in_integer;
                    push_element_into_bloom_filter(bf, &variable_in_integer, sizeof(variable_in_integer));
                }
            }
        }
        count += 1;
    }
    memcpy(rte->bitset, bf->bitset, sizeof(unsigned char) * bf->bf_effective_bytes);
    reset_bloom_filter(bf);
    if (MULTIPATH_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        add_routing_table_entry_to_abpt_in_hash_format(pvs->abpt, rte);
    } else {
        printk(KERN_EMERG "unsupported routing table version number");
    }
    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INSERT_ROUTING_TABLE_ENTRY: source_id: %d, destination_id: %d, path_length: %d, link_identifier_index: %d, node_index: %d",
             source_id, destination_id, path_length, link_identifier_index, node_index);
    return send_reply(response_buffer, info);
}

/**
 * netlink_insert_interface_table_entry_handler() - 插入一条接口表项并更新布隆过滤器快照
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷（逗号分隔）：index, link_identifier, ifindex, source_node_id, target_node_id,
 * 以及点分十进制 peer_ip（最后一项由 in_aton 解析）。
 *
 * Return: 0 或负数错误码。
 */
int netlink_insert_interface_table_entry_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    const char *delimiter = ",";
    int count = 0;
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int index;
    int link_identifier;
    int ifindex;
    int source_node_id;
    int target_node_id;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    int variable_in_integer;
    __be32 peer_ip_address;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            if (count == 0) {
                variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
                index = variable_in_integer;
            } else if (count == 1) {
                variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
                link_identifier = variable_in_integer;
            } else if (count == 2) {
                variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
                ifindex = variable_in_integer;
            } else if (count == 3) {
                variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
                source_node_id = variable_in_integer;
            } else if (count == 4) {
                variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
                target_node_id = variable_in_integer;
            } else if (count == 5) {
                peer_ip_address = in_aton(variable_in_str);
            } else {
                printk(KERN_EMERG "there are more than six params in CMD_INSERT_INTERFACE_TABLE_ENTRY");
                return -EINVAL;
            }
        }
        count += 1;
    }
    struct InterfaceTableEntry *ite = init_ite(index, ifindex, (int) (pvs->bloom_filter->bf_effective_bytes));
    push_element_into_bloom_filter(pvs->bloom_filter, &link_identifier, sizeof(link_identifier));
    ite->link_identifier = link_identifier;
    ite->interface = dev_get_by_index(current_ns, ifindex);
    ite->peer_ip_address = peer_ip_address;
    ite->source_node_id = source_node_id;
    ite->target_node_id = target_node_id;
    dev_put(ite->interface);
    memcpy(ite->bitset, pvs->bloom_filter->bitset, pvs->bloom_filter->bf_effective_bytes);
    reset_bloom_filter(pvs->bloom_filter);
    add_ite_to_abit(pvs->abit, ite);
    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_INSERT_INTERFACE_TABLE_ENTRY: index: %d, link_identifier: %d, ifindex: %d, ifname: %s",
             index, link_identifier, ifindex, pvs->abit->interfaces[index]->interface->name);
    return send_reply(response_buffer, info);
}

/**
 * netlink_set_lir_single_time_encoding_count_handler() - 设置 LiR 单次编码插入的元素个数
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：单个十进制整数。
 *
 * Return: 0 或负数错误码。
 */
int netlink_set_lir_single_time_encoding_count_handler(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    int lir_single_time_encoding_count;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    lir_single_time_encoding_count = (int) (simple_strtol(receive_buffer, NULL, 10));
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    pvs->lir_single_time_encoding_count = lir_single_time_encoding_count;
    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_SET_LIR_SINGLE_TIME_ENCODING_COUNT: lir_single_time_encoding_count: %d",
             lir_single_time_encoding_count);
    return send_reply(response_buffer, info);
}


/**
 * print_routing_table_entries() - 调试：将 abrt 路由项打印到 dmesg 并回复简短状态
 * @request: 请求 skb
 * @info: genl 属性（载荷中的整数仅用于日志占位，语义由调用方约定）
 *
 * Return: 0 或负数错误码。
 */
int print_routing_table_entries(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    int useless_param;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    useless_param = (int) (simple_strtol(receive_buffer, NULL, 10));
    printk(KERN_EMERG "free memory in net namespace, useless_param: %d\n", useless_param);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if (NULL == pvs) {
        printk(KERN_EMERG "pvs == NULL\n");
        return -EINVAL;
    } else {
        printk(KERN_EMERG "abrt number of routes: %d\n", pvs->abrt->number_of_routes);
        int index;
        for (index = 0; index < pvs->abrt->number_of_routes; index++) {
            struct RoutingTableEntry *rte = pvs->abrt->routes[index];
            if (NULL != rte) {
                printk(KERN_EMERG "rte source: %d, destination: %d, path_length: %d\n",
                       rte->source_id, rte->destination_id, rte->path_length);
            } else {
                printk(KERN_EMERG "rte is NULL at index: %d\n", index);
            }
        }
    }
    snprintf(response_buffer, sizeof(response_buffer), "CMD_PRINT_ROUTING_TABLE_ENTRIES: node: %d useless param: %d",
             pvs->node_id, useless_param);
    return send_reply(response_buffer, info);
}


int netlink_set_sec_path_mab_route(struct sk_buff *request, struct genl_info *info){
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH) {
//        printk(KERN_EMERG "set sec path mab route for fixed batch \n");
        return netlink_set_sec_path_mab_route_for_fixed_batch(request, info);
    } else {
//        printk(KERN_EMERG "set sec path mab route for dynamic batch \n");
        return netlink_set_sec_path_mab_route_for_dynamic_batch(request, info);
    }
}

/**
 * netlink_set_sec_path_mab_route_for_dynamic_batch 适应动态 batch 的路径设置
 * @param request
 * @param info
 * @return
 */
int netlink_set_sec_path_mab_route_for_dynamic_batch(struct sk_buff* request, struct genl_info * info){
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    const char *delimeter = ",";
    int count = 0;
    struct SecPathMabRoute *sec_path_mab_route = (struct SecPathMabRoute *) kmalloc(sizeof(struct SecPathMabRoute),
                                                                                    GFP_ATOMIC);
    sec_path_mab_route->sample_sequence = NULL;


    int source_id;
    int destination_id;
    int number_of_link_identifiers;
    int first_link_identifier;
    int number_of_sample_nodes;
    int sample_node;
    int mini_batch_size;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                source_id = variable_in_integer;
                sec_path_mab_route->source_id = source_id;
            } else if (count == 1) {
                destination_id = variable_in_integer;
                sec_path_mab_route->destination_id = destination_id;
            } else if (count == 2) {
                number_of_link_identifiers = variable_in_integer;
                /* 首个 link id 仅用于出接口，不计入 link_identifiers[] */
                sec_path_mab_route->number_of_link_identifiers = number_of_link_identifiers - 1;
                sec_path_mab_route->link_identifiers = (int *) kmalloc(
                        sizeof(int) * sec_path_mab_route->number_of_link_identifiers, GFP_ATOMIC);
            } else if (count <= 2 + number_of_link_identifiers) {
                if (count == 3) {
                    first_link_identifier = variable_in_integer;
                } else {
                    sec_path_mab_route->link_identifiers[count - 4] = variable_in_integer;
                }
            } else if (count == 2 + number_of_link_identifiers + 1) {
                number_of_sample_nodes = variable_in_integer;
                sec_path_mab_route->number_of_sample_nodes = number_of_sample_nodes;
                sec_path_mab_route->sample_node_ids = (int *) kmalloc(sizeof(int) * number_of_sample_nodes, GFP_ATOMIC);
            } else if (count <= 3 + number_of_link_identifiers + number_of_sample_nodes) {
                sample_node = variable_in_integer;
                sec_path_mab_route->sample_node_ids[count - 4 - number_of_link_identifiers] = sample_node;
            } else if (count == 4 + number_of_link_identifiers + number_of_sample_nodes) {
                mini_batch_size = variable_in_integer;
            }
            else {
                free_sec_path_mab_route(sec_path_mab_route);
                printk(KERN_EMERG "there are more than %d params in CMD_SET_SEC_PATH_MAB_ROUTE\n",
                       5 + number_of_link_identifiers + number_of_sample_nodes);
                return -EINVAL;
            }
        }
        count += 1;
    }

    struct InterfaceTableEntry *output_ite = NULL;
    output_ite = find_ite_in_abit_with_link_identifier(pvs->abit, first_link_identifier);
    if (NULL != output_ite) {
        sec_path_mab_route->ite = output_ite;
    } else {
        printk(KERN_EMERG "cannot find output interface with link identifier: %d\n", first_link_identifier);
        free_sec_path_mab_route(sec_path_mab_route);
        return -EINVAL;
    }

    // 刚刚进行换路, 肯定需要进行采样包的发送
    set_send_sample_packets(pvs->sec_path_mab_settings, true);

    if (NULL != pvs->hbale) {
//        printk(KERN_EMERG "current retrieve epoch: %d\n", pvs->sec_path_mab_settings->current_retrieve_epoch);
        struct StatisticsForSingleEpoch *sfse = init_sfse(number_of_sample_nodes,pvs->sec_path_mab_settings->current_retrieve_epoch, mini_batch_size);
        int result = add_sfse_to_hbale(pvs->hbale, sfse);
        if (result != ADD_SUCCESS) {
            free_sec_path_mab_route(sec_path_mab_route);
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbale is NULL\n");
        free_sec_path_mab_route(sec_path_mab_route);
        return -EINVAL;
    }

    if (NULL != pvs->hbace) {
        struct HashBasedAckCacheTableForSingleEpoch *hbase = init_hbase(100, pvs->sec_path_mab_settings->current_retrieve_epoch);
        int result = add_hbase_to_hbace(pvs->hbace, hbase);
        if (result != ADD_SUCCESS) {
            free_sec_path_mab_route(sec_path_mab_route);
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbace is NULL\n");
        free_sec_path_mab_route(sec_path_mab_route);
        return -EINVAL;
    }

    if (NULL != pvs->sec_path_mab_settings->selected_route) {
        free_sec_path_mab_route(pvs->sec_path_mab_settings->selected_route);
    }

    pvs->sec_path_mab_settings->selected_route = sec_path_mab_route;

    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_SET_SEC_PATH_MAB_ROUTE: source id: %d, destination_id: %d, number_of_link_identifiers: %d, number_of_sample_nodes: %d",
             source_id, destination_id, number_of_link_identifiers, number_of_sample_nodes);
    return send_reply(response_buffer, info);
}

/**
 * netlink_set_sec_path_mab_route() - 配置安全路径 MAB 实验用路由及 per-epoch ACK 表
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷为逗号分隔整数，顺序与解析变量 count 一致：
 * - source_id, destination_id
 * - number_of_link_identifiers：用户态给出的 link 域个数（含用于选取出接口的第一个 link id）；
 *   内核在结构体中保存 link_identifiers 条数为该值减 1（首 link 仅用于 ite 查找）
 * - 共 number_of_link_identifiers 个 link id（首项即 first_link_identifier）
 * - number_of_sample_nodes，再跟同等数量的 sample node id
 * - batch_size：传给 generate_sequence() 生成采样序列
 *
 * 示例：1,14,5,1,21,25,29,17,5,3,6,9,12,14,200
 * 对应 source=1, dest=14，5 个 link 字段，5 个采样节点，batch=200。
 *
 * 成功时递增 current_epoch，向 hbale/hbace 注册新 epoch 表，并替换 selected_route。
 *
 * Return: 0 或负数错误码。
 */
int netlink_set_sec_path_mab_route_for_fixed_batch(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char *receive_buffer_ptr;
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    const char *delimeter = ",";
    int count = 0;
    struct SecPathMabRoute *sec_path_mab_route = (struct SecPathMabRoute *) kmalloc(sizeof(struct SecPathMabRoute),
                                                                                    GFP_ATOMIC);
    sec_path_mab_route->sample_sequence = NULL;

    // 进行变量的定义
    int source_id;
    int destination_id;
    int batch_size;
    int number_of_link_identifiers;
    int first_link_identifier;
    int number_of_sample_nodes;
    int sample_count;

    int link_identifier_index = 0;
    int sample_node_index = 0;
    int sample_count_index = 0;
    int* sample_counts = NULL;

    int sample_node;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                source_id = variable_in_integer;
                sec_path_mab_route->source_id = source_id;
            } else if (count == 1) {
                destination_id = variable_in_integer;
                sec_path_mab_route->destination_id = destination_id;
            } else if (count == 2) {
                number_of_link_identifiers = variable_in_integer;
                /* 首个 link id 仅用于出接口，不计入 link_identifiers[] */
                sec_path_mab_route->number_of_link_identifiers = number_of_link_identifiers - 1;
                sec_path_mab_route->link_identifiers = (int *) kmalloc(
                        sizeof(int) * sec_path_mab_route->number_of_link_identifiers, GFP_ATOMIC);
            } else if (count <= 2 + number_of_link_identifiers) {
                if (count == 3) {
                    first_link_identifier = variable_in_integer;
                } else {
//                    sec_path_mab_route->link_identifiers[count - 4] = variable_in_integer;
                    sec_path_mab_route->link_identifiers[link_identifier_index++] = variable_in_integer;
                }
            } else if (count == 3 + number_of_link_identifiers) {
                number_of_sample_nodes = variable_in_integer;
                sample_counts = (int*)kmalloc(sizeof(int) * number_of_sample_nodes, GFP_KERNEL);
                sec_path_mab_route->number_of_sample_nodes = number_of_sample_nodes;
                sec_path_mab_route->sample_node_ids = (int *) kmalloc(sizeof(int) * number_of_sample_nodes, GFP_ATOMIC);
            } else if (count <= 3 + number_of_link_identifiers + number_of_sample_nodes) {
                sample_node = variable_in_integer;
//                sec_path_mab_route->sample_node_ids[count - 4 - number_of_link_identifiers] = sample_node;
                sec_path_mab_route->sample_node_ids[sample_node_index++] = sample_node;
            } else if(count == 4 + number_of_link_identifiers + number_of_sample_nodes){
                batch_size = variable_in_integer;
            } else if (count <= 4 + number_of_link_identifiers + number_of_sample_nodes + number_of_sample_nodes){
                sample_count = variable_in_integer;
                sample_counts[sample_count_index++] = sample_count;
            } else {
                free_sec_path_mab_route(sec_path_mab_route);
                printk(KERN_EMERG "there are more than %d params in CMD_SET_SEC_PATH_MAB_ROUTE\n",
                       5 + number_of_link_identifiers + number_of_sample_nodes);
                return -EINVAL;
            }
        }
        count += 1;
    }

    struct InterfaceTableEntry *output_ite = NULL;
    output_ite = find_ite_in_abit_with_link_identifier(pvs->abit, first_link_identifier);
    if (NULL != output_ite) {
        sec_path_mab_route->ite = output_ite;
    } else {
        printk(KERN_EMERG "cannot find output interface with link identifier: %d\n", first_link_identifier);
        free_sec_path_mab_route(sec_path_mab_route);
        return -EINVAL;
    }

    // 进行 sequence 的生成
    sec_path_mab_route->sample_sequence = generate_sequence(number_of_sample_nodes, batch_size, sample_counts);

    // 进行 sample_counts 释放
    if(NULL != sample_counts){
        kfree(sample_counts);
    }

    // 进行发送 epoch 的 ++
    pvs->sec_path_mab_settings->current_epoch += 1;

    if (NULL != pvs->hbale) {
        struct StatisticsForSingleEpoch *sfse = init_sfse(number_of_sample_nodes,
                                                          pvs->sec_path_mab_settings->current_epoch,
                                                          batch_size);
        int result = add_sfse_to_hbale(pvs->hbale, sfse);
        if (result != ADD_SUCCESS) {
            free_sec_path_mab_route(sec_path_mab_route);
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbale is NULL\n");
        free_sec_path_mab_route(sec_path_mab_route);
        return -EINVAL;
    }

    if (NULL != pvs->hbace) {
        struct HashBasedAckCacheTableForSingleEpoch *hbase = init_hbase(100, pvs->sec_path_mab_settings->current_epoch);
        int result = add_hbase_to_hbace(pvs->hbace, hbase);
        if (result != ADD_SUCCESS) {
            free_sec_path_mab_route(sec_path_mab_route);
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbace is NULL\n");
        free_sec_path_mab_route(sec_path_mab_route);
        return -EINVAL;
    }

    if (NULL != pvs->sec_path_mab_settings->selected_route) {
        free_sec_path_mab_route(pvs->sec_path_mab_settings->selected_route);
    }

    pvs->sec_path_mab_settings->selected_route = sec_path_mab_route;


    snprintf(response_buffer, sizeof(response_buffer),
             "CMD_SET_SEC_PATH_MAB_ROUTE: source id: %d, destination_id: %d, number_of_link_identifiers: %d, number_of_sample_nodes: %d",
             source_id, destination_id, number_of_link_identifiers, number_of_sample_nodes);
    return send_reply(response_buffer, info);
}


int netlink_reset_sec_path_mab_route(struct sk_buff *request, struct genl_info *info){
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH){
        return netlink_reset_sec_path_mab_route_for_fixed_batch(request, info);
    } else {
        return netlink_reset_sec_path_mab_route_for_dynamic_batch(request, info);
    }
}

/**
 * netlink_reset_sec_path_mab_route() - 重置当前 MAB 路由状态并开启新 epoch 的 ACK 表
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 调用 reset_sec_path_mab_route_sequence(selected_route)，递增 current_epoch，并按 selected_route
 * 中的采样节点数为新区间创建 sfse / hbase。
 *
 * Return: 0 或负数错误码。
 */
int netlink_reset_sec_path_mab_route_for_fixed_batch(struct sk_buff *request, struct genl_info *info) {
    char response_buffer[1024];
    char *receive_buffer_ptr;
    const char *delimiter = ",";
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int count = 0;

    // 进行当前发送 epoch ++
    pvs->sec_path_mab_settings->current_epoch += 1;

    // 变量声明
    int batch_size;
    int sample_count;
    int sample_count_index = 0;
    int* sample_counts = (int*)kmalloc(sizeof(int) * pvs->sec_path_mab_settings->selected_route->number_of_sample_nodes, GFP_KERNEL);

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimiter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if(count == 0){
                batch_size = variable_in_integer;
            } else if (count <= pvs->sec_path_mab_settings->selected_route->number_of_sample_nodes){
                sample_count = variable_in_integer;
                sample_counts[sample_count_index++] = sample_count;
            } else {
                printk(KERN_EMERG "there are more than %d params in CMD_RESET_SEC_PATH_MAB_ROUTE\n", pvs->sec_path_mab_settings->selected_route->number_of_sample_nodes + 1);
                return -EINVAL;
            }
        }
        count += 1;
    }


    // 进行 sequence 的重新生成
    reset_sec_path_mab_route_sequence(pvs->sec_path_mab_settings->selected_route, batch_size, sample_counts);

    // 进行 sample_counts 的释放
    if(NULL != sample_counts){
        kfree(sample_counts);
    }

    int number_of_sample_nodes = pvs->sec_path_mab_settings->selected_route->number_of_sample_nodes;
    if (NULL != pvs->hbale) {
        struct StatisticsForSingleEpoch *sfse = init_sfse(number_of_sample_nodes,
                                                          pvs->sec_path_mab_settings->current_epoch,
                                                          batch_size);
        int result = add_sfse_to_hbale(pvs->hbale, sfse);
        if (result != ADD_SUCCESS) {
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbale is NULL\n");
    }

    if (NULL != pvs->hbace) {
        struct HashBasedAckCacheTableForSingleEpoch *hbase = init_hbase(100, pvs->sec_path_mab_settings->current_epoch);
        int result = add_hbase_to_hbace(pvs->hbace, hbase);
        if (result != ADD_SUCCESS) {
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbace is NULL\n");
    }

    snprintf(response_buffer, sizeof(response_buffer), "CMD_RESET_SEC_PATH_MAB_ROUTE succeed");
    return send_reply(response_buffer, info);
}


int netlink_reset_sec_path_mab_route_for_dynamic_batch(struct sk_buff *request, struct genl_info *info){
    char response_buffer[1024];
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);

    // 进行变量的声明
    int mini_batch_size;

    // 进行消息的拷贝
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }

    // 进行变量的获取
    mini_batch_size = (int)(simple_strtol(receive_buffer, NULL, 10));


    set_send_sample_packets(pvs->sec_path_mab_settings, true);

    int number_of_sample_nodes = pvs->sec_path_mab_settings->selected_route->number_of_sample_nodes;
    if (NULL != pvs->hbale) {
        struct StatisticsForSingleEpoch *sfse = init_sfse(number_of_sample_nodes,
                                                          pvs->sec_path_mab_settings->current_retrieve_epoch,
                                                          mini_batch_size);
        int result = add_sfse_to_hbale(pvs->hbale, sfse);
        if (result != ADD_SUCCESS) {
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbale is NULL\n");
    }

    if (NULL != pvs->hbace) {
        struct HashBasedAckCacheTableForSingleEpoch *hbase = init_hbase(100, pvs->sec_path_mab_settings->current_retrieve_epoch);
        int result = add_hbase_to_hbace(pvs->hbace, hbase);
//        print_status(result);
        if (result != ADD_SUCCESS) {
            return -EINVAL;
        }
    } else {
        LOG_WITH_PREFIX("hbace is NULL\n");
    }

    snprintf(response_buffer, sizeof(response_buffer), "CMD_RESET_SEC_PATH_MAB_ROUTE succeed");
    return send_reply(response_buffer, info);
}

/**
 * netlink_set_router_type() - 设置路由器工作模式（普通 / 路径验证）
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：单个十进制整数，须为 ROUTER_TYPE_NORMAL 或 ROUTER_TYPE_PATH_VALIDATION。
 *
 * Return: 0 或负数错误码。
 */
int netlink_set_router_type(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    int router_type;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    router_type = (int) (simple_strtol(receive_buffer, NULL, 10));
    if ((router_type != ROUTER_TYPE_NORMAL) && (router_type != ROUTER_TYPE_PATH_VALIDATION)) {
        printk(KERN_EMERG "invalid router type: %d\n", router_type);
        return -EINVAL;
    }

    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);

    pvs->router_type = router_type;

    snprintf(response_buffer, sizeof(response_buffer), "CMD_SET_ROUTER_TYPE: router id: %d : router type %d\n",
             pvs->router_type, pvs->node_id);
    return send_reply(response_buffer, info);
}

int netlink_set_sec_path_mab_type(struct sk_buff* request, struct genl_info *info){
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    int sec_path_mab_type;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }

    sec_path_mab_type = (int)(simple_strtol(receive_buffer, NULL, 10));
    if((sec_path_mab_type != SEC_PATH_MAB_TYPE_FIXED_BATCH) && (sec_path_mab_type != SEC_PATH_MAB_TYPE_DYNAMIC_BATCH)) {
        printk(KERN_EMERG "invalid sec_path_mab_type: %d\n", sec_path_mab_type);
        return -EINVAL;
    }

    struct PathValidationStructure* pvs = get_pvs_from_ns(current_ns);
    pvs->sec_path_mab_settings->sec_path_mab_type = sec_path_mab_type;

    snprintf(response_buffer, sizeof(response_buffer), "CMD_SET_SEC_PATH_MAB_TYPE: %d", sec_path_mab_type);
    return send_reply(response_buffer, info);
}

/**
 * netlink_set_router_malicious_parameters() - 设置实验用恶意参数（破坏数据 / ACK 的概率区间）
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：逗号分隔四个整数 —
 * corrupt_ratio_start, corrupt_ratio_end, corrupt_special_ratio_start, corrupt_special_ratio_end，
 * 写入 sec_path_mab_settings->malicious_params。
 *
 * Return: 0 或负数错误码。
 */
int netlink_set_router_malicious_parameters(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    char *receive_buffer_ptr;
    const char *delimeter = ",";
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int count = 0;
    int corrupt_ratio_start;
    int corrupt_ratio_end;
    int corrupt_special_ratio_start;
    int corrupt_special_ratio_end;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                corrupt_ratio_start = variable_in_integer;
                pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_start = corrupt_ratio_start;
            } else if (count == 1) {
                corrupt_ratio_end = variable_in_integer;
                pvs->sec_path_mab_settings->malicious_params->corrupt_ratio_end = corrupt_ratio_end;
            } else if (count == 2) {
                corrupt_special_ratio_start = variable_in_integer;
                pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_start = corrupt_special_ratio_start;
            } else if (count == 3) {
                corrupt_special_ratio_end = variable_in_integer;
                pvs->sec_path_mab_settings->malicious_params->corrupt_special_ratio_end = corrupt_special_ratio_end;
            } else {
                printk(KERN_EMERG "there are more than four parameters\n");
                return -EINVAL;
            }
        }
        count += 1;
    }

    snprintf(response_buffer, sizeof(response_buffer), "CMD_SET_MALICIOUS_PARAMS: %d-%d | %d-%d\n",
             corrupt_ratio_start, corrupt_ratio_end,
             corrupt_special_ratio_start, corrupt_special_ratio_end);
    return send_reply(response_buffer, info);
}

int netlink_retrieve_kernel_information(struct sk_buff *request, struct genl_info *info){
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if(pvs->sec_path_mab_settings->sec_path_mab_type == SEC_PATH_MAB_TYPE_FIXED_BATCH) {
        return netlink_retrieve_kernel_information_for_fixed_batch(request, info);
    } else {
        return netlink_retrieve_kernel_information_for_dynamic_batch(request, info);
    }
}


/**
 * netlink_retrieve_kernel_information() - 取出指定 epoch 的 ACK 列表，拼成逗号分隔字符串回复后释放该 epoch 节点
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：十进制 epoch_id。从 hbale 查找 sfse，将 received_acks 拼入 response_buffer，
 * 随后 hlist_del 并 free_sfse()。
 *
 * Return: 0 或负数错误码。
 */
//int netlink_retrieve_kernel_information_for_fixed_batch_original_version(struct sk_buff *request, struct genl_info *info) {
//    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
//    char response_buffer[1024];
//
//    response_buffer[0] = '\0';
//    struct net *current_ns = sock_net(request->sk);
//    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
//    {
//        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
//        if (err)
//            return err;
//    }
//    if (NULL == pvs->hbale) {
//        snprintf(response_buffer, sizeof(response_buffer), "Err: hbale is NULL\n");
//        return send_reply(response_buffer, info);
//    }
//
//    struct StatisticsForSingleEpoch *sfse = find_sfse_in_hbale(pvs->hbale, pvs->sec_path_mab_settings->current_retrieve_epoch);
//    if (NULL == sfse) {
//        snprintf(response_buffer, sizeof(response_buffer), "Err: cannot find sfse with epoch id: %d\n", pvs->sec_path_mab_settings->current_retrieve_epoch);
//        return send_reply(response_buffer, info);
//    }
//
//    struct HashBasedAckCacheTableForSingleEpoch *hbase = find_hbase_in_hbace(pvs->hbace, pvs->sec_path_mab_settings->current_retrieve_epoch);
//    if (NULL == hbase) {
//        snprintf(response_buffer, sizeof(response_buffer), "Err: cannot find hbase with epoch id: %d\n", pvs->sec_path_mab_settings->current_retrieve_epoch);
//        return send_reply(response_buffer, info);
//    }
//
//    // 1. 第1个条件是所有的 packets 全部丢出去了
//    int remained_packets = sfse->batch_size - get_sfse_sampling_packets(sfse);
//    bool first_condition = (remained_packets == 0);
//    if(!first_condition){
//        snprintf(response_buffer, sizeof(response_buffer),
//                 "Err: first condition is not fulfilled, there are %d scheduled packets are not forwarded", remained_packets);
//        printk(KERN_EMERG "%s\n", response_buffer);
//        return send_reply(response_buffer, info);
//    }
//
//    // 2. 第2个条件 （是否当前时间戳 > 超时时间戳）
//    u64 current_timestamp = ktime_get_us();
//    sfse->timeout_timestamp = get_timeout_timestamp(sfse);
//    bool third_condition = current_timestamp > sfse->timeout_timestamp;
//    if (!third_condition) {
//        snprintf(response_buffer, sizeof(response_buffer),
//                 "Err: second condition is not fulfilled, remain: %llu us via retrieving epoch %d",
//                 sfse->timeout_timestamp - current_timestamp, pvs->sec_path_mab_settings->current_retrieve_epoch);
//        return send_reply(response_buffer, info);
//    }
//
//    // 4. 如果2个条件都被满足了, 那么就可以安全地返回 ACK 列表了
//    write_response_string_for_fixed_batch(sfse, response_buffer, pvs->sec_path_mab_settings->current_retrieve_epoch);
//    pvs->sec_path_mab_settings->current_retrieve_epoch++;
//
//    // 5. 如果都返回了, 就可以进行 sfse 的释放了
//    spin_lock_bh(&(pvs->hbale->lock));
//    free_sfse_with_pointer(sfse);
//    spin_unlock_bh(&(pvs->hbale->lock));
//
//    // 6. 如果都返回了, 也可以进行 hbase 的释放了
//    spin_lock_bh(&(pvs->hbace->lock));
//    free_hbase_with_pointer(hbase);
//    spin_unlock_bh(&(pvs->hbace->lock));
//
//    return send_reply(response_buffer, info);
//}


/**
 * netlink_retrieve_kernel_information() - 取出指定 epoch 的 ACK 列表，拼成逗号分隔字符串回复后释放该 epoch 节点
 * @request: 请求 skb
 * @info: genl 属性
 *
 * 载荷：十进制 epoch_id。从 hbale 查找 sfse，将 received_acks 拼入 response_buffer，
 * 随后 hlist_del 并 free_sfse()。
 *
 * Return: 0 或负数错误码。
 */
int netlink_retrieve_kernel_information_for_fixed_batch(struct sk_buff *request, struct genl_info *info) {
    int err_type; // 错误的类型 (可能是 first condition not satisfied 也可能是 second condition not satisfied)
    u64 remained_us = 0; // 对应于第1个错误类型
    int remained_packets; // 对应于第2个错误类型

    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char retrieved_acks_string[1024];
    retrieved_acks_string[0] = '\0';
    char response_buffer[1024];
    response_buffer[0] = '\0';
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    if (NULL == pvs->hbale) {
        snprintf(response_buffer, sizeof(response_buffer), "Err: hbale is NULL\n");
        return send_reply(response_buffer, info);
    }


    int number_of_retrieved_epochs = 0; // 代表 retrieve 回来的 epoch 数量
    while (true) {
        struct StatisticsForSingleEpoch *sfse = find_sfse_in_hbale(pvs->hbale, pvs->sec_path_mab_settings->current_retrieve_epoch);
        if (NULL == sfse) {
            snprintf(response_buffer, sizeof(response_buffer), "Err: cannot find sfse with epoch id: %d\n", pvs->sec_path_mab_settings->current_retrieve_epoch);
            return send_reply(response_buffer, info);
        }

        struct HashBasedAckCacheTableForSingleEpoch *hbase = find_hbase_in_hbace(pvs->hbace, pvs->sec_path_mab_settings->current_retrieve_epoch);
        if (NULL == hbase) {
            snprintf(response_buffer, sizeof(response_buffer), "Err: cannot find hbase with epoch id: %d\n", pvs->sec_path_mab_settings->current_retrieve_epoch);
            return send_reply(response_buffer, info);
        }

        // 1. 第1个条件是所有的 packets 全部丢出去了
        remained_packets = sfse->batch_size - get_sfse_sampling_packets(sfse);
        bool first_condition = (remained_packets == 0);
        if(!first_condition){
            err_type = 1;
            break;
        }

        // 2. 第2个条件 （是否当前时间戳 > 超时时间戳）
        u64 current_timestamp = ktime_get_us();
        sfse->timeout_timestamp = get_timeout_timestamp(sfse);
        bool second_condition = current_timestamp > sfse->timeout_timestamp;
        if (!second_condition) {
            remained_us = sfse->timeout_timestamp - current_timestamp;
            err_type = 2;
            break;
        }

        // 3. 如果2个条件都被满足了, 那么就可以安全地返回 ACK 列表了
        write_response_string_for_fixed_batch(sfse, retrieved_acks_string, pvs->sec_path_mab_settings->current_retrieve_epoch);
//        printk(KERN_EMERG "retrieved_acks_string: %s\n", retrieved_acks_string);
        pvs->sec_path_mab_settings->current_retrieve_epoch++;


        // 4. 如果都返回了, 就可以进行 sfse 的释放了
        spin_lock_bh(&(pvs->hbale->lock));
        free_sfse_with_pointer(sfse);
        spin_unlock_bh(&(pvs->hbale->lock));

        // 5. 如果都返回了, 也可以进行 hbase 的释放了
        spin_lock_bh(&(pvs->hbace->lock));
        free_hbase_with_pointer(hbase);
        spin_unlock_bh(&(pvs->hbace->lock));

        // 6. 本次取回的 feedback 数量 + 1
        number_of_retrieved_epochs += 1;
    }

    // 如果没有进行任何一个 epoch 的获取的话, 那么直接进行错误的返回
    if(number_of_retrieved_epochs == 0){
        if(err_type == 1){
            snprintf(response_buffer, sizeof(response_buffer), "Err: first condition is not fulfilled, there are %d scheduled packets are not forwarded", remained_packets);
        } else {
            snprintf(response_buffer, sizeof(response_buffer), "Err: second condition is not fulfilled, remain: %llu us via retrieving epoch %d",
                     remained_us, pvs->sec_path_mab_settings->current_retrieve_epoch);
        }
    } else {
        // 反之, 如果进行了 epoch 的获取的话
        snprintf(response_buffer, sizeof(response_buffer), "%d,%s", number_of_retrieved_epochs, retrieved_acks_string);
//        printk(KERN_EMERG "response_buffer: %s\n", response_buffer);
    }


    return send_reply(response_buffer, info);
}

int netlink_retrieve_kernel_information_for_dynamic_batch(struct sk_buff *request, struct genl_info *info){
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];

    response_buffer[0] = '\0';
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int epoch_id;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    epoch_id = pvs->sec_path_mab_settings->current_retrieve_epoch; // 第一次获取 epoch = 1 的, 下一次获取 epoch = 2 的，以此类推
    if (NULL == pvs->hbale) {
        snprintf(response_buffer, sizeof(response_buffer), "Err: hbale is NULL\n");
        return send_reply(response_buffer, info);
    }

    struct StatisticsForSingleEpoch *sfse = find_sfse_in_hbale(pvs->hbale, epoch_id);
    if (NULL == sfse) {
        snprintf(response_buffer, sizeof(response_buffer), "Err: cannot find sfse with epoch id: %d\n", epoch_id);
        return send_reply(response_buffer, info);
    }

    struct HashBasedAckCacheTableForSingleEpoch *hbase = find_hbase_in_hbace(pvs->hbace, epoch_id);
    if (NULL == hbase) {
        snprintf(response_buffer, sizeof(response_buffer), "Err: cannot find hbase with epoch id: %d\n", epoch_id);
        return send_reply(response_buffer, info);
    }

    // 1. 第1个条件是否每个节点都收到了足够数量的 ack 从而确保对于 rtt 的估计是准确的
    if(!sfse->already_collected_acks){
        bool first_condition = received_enough_acks(sfse, pvs->sec_path_mab_settings->min_ack_for_rtt_estimation);
        if (!first_condition) {
            snprintf(response_buffer, sizeof(response_buffer),
                     "Err: first condition is not fulfilled, there are some nodes that have received less than %d acks in epoch %d",
                     pvs->sec_path_mab_settings->min_ack_for_rtt_estimation, epoch_id);
            return send_reply(response_buffer, info);
        } else {
            // 如果满足了第一个条件那么当前的 sec_path_mab_settings 之中的 bool 设置为 true, 代表的是不用再进行检测包的发送了
            set_send_sample_packets(pvs->sec_path_mab_settings, false);
            sfse->already_collected_acks = true;
        }
        // 150 + RTT (最远) + RTT (最远)
        sfse->collect_enough_ack_time_stamp = ktime_get_us();
    }


    // 2. 第2个条件 （是否当前时间戳 > 超时时间戳）
    u64 current_timestamp = ktime_get_us();
    sfse->timeout_timestamp = get_timeout_timestamp(sfse);
    bool second_condition = current_timestamp > sfse->timeout_timestamp;
    if (!second_condition) {
//        printk(KERN_EMERG "Err: second condition is not fulfilled, remain: %llu us in epoch %d, sent %d packets",sfse->timeout_timestamp - current_timestamp, epoch_id, sfse->number_of_sampling_packets);
        snprintf(response_buffer, sizeof(response_buffer),
                 "Err: second condition is not fulfilled, remain: %llu us in epoch %d, sent %d packets",
                 sfse->timeout_timestamp - current_timestamp, epoch_id, sfse->number_of_sampling_packets);
        return send_reply(response_buffer, info);
    }

    // 3. 如果2个条件都被满足了, 那么就可以安全地返回 ACK 列表了
    sfse->reach_timeout_time_stamp = ktime_get_us();  // 更新 sending_time_elapsed
    write_response_string_for_dynamic_batch(sfse, response_buffer, pvs->sec_path_mab_settings->current_retrieve_epoch);

//    printk(KERN_EMERG "retrieve epoch: %d\n", pvs->sec_path_mab_settings->current_retrieve_epoch);
    pvs->sec_path_mab_settings->current_retrieve_epoch++;

    // 4. 如果都返回了, 就可以进行 sfse 的释放了
    spin_lock_bh(&(pvs->hbale->lock));
    free_sfse_with_pointer(sfse);
    spin_unlock_bh(&(pvs->hbale->lock));

    // 5. 如果都返回了, 也可以进行 hbase 的释放了
    spin_lock_bh(&(pvs->hbace->lock));
    free_hbase_with_pointer(hbase);
    spin_unlock_bh(&(pvs->hbace->lock));

    return send_reply(response_buffer, info);
}

int netlink_set_scheduled_malicious_params(struct sk_buff *request, struct genl_info *info) {
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    char *receive_buffer_ptr;
    const char *delimeter = ",";
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    int count = 0;

    // define parameters
    int epoch_employed;
    int corrupt_ratio_start;
    int corrupt_ratio_end;
    int corrupt_special_ratio_start;
    int corrupt_special_ratio_end;

    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }

    receive_buffer_ptr = receive_buffer;
    while (true) {
        char *variable_in_str = strsep(&receive_buffer_ptr, delimeter);
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                epoch_employed = variable_in_integer;
            } else if (count == 1) {
                corrupt_ratio_start = variable_in_integer;
            } else if (count == 2) {
                corrupt_ratio_end = variable_in_integer;
            } else if (count == 3) {
                corrupt_special_ratio_start = variable_in_integer;
            } else if (count == 4) {
                corrupt_special_ratio_end = variable_in_integer;
            } else {
                printk(KERN_EMERG "there are more than five parameters\n");
                return -EINVAL;
            }
        }
        count += 1;
    }

    struct ScheduledCorruptRatio *scheduled_corrupt_ratio = init_scheduled_corrupt_ratio(epoch_employed,
                                                                                         corrupt_ratio_start,
                                                                                         corrupt_ratio_end);

    struct ScheduledCorruptSpecialPacketRatio *scheduled_corrupt_special_packet_ratio = init_scheduled_corrupt_special_packet_ratio(
            epoch_employed,
            corrupt_special_ratio_start,
            corrupt_special_ratio_end);

    int result_add_corrupt_ratio = add_corrupt_ratio_entry_to_llbpmt(pvs->llbmpt, scheduled_corrupt_ratio);
    int result_add_corrupt_special_packet_ratio = add_corrupt_special_packet_ratio_entry_to_llbpmt(pvs->llbmpt, scheduled_corrupt_special_packet_ratio);
    if (0 != (result_add_corrupt_ratio || result_add_corrupt_special_packet_ratio)) {
        snprintf(response_buffer, sizeof(response_buffer), "Err: failed to add malicious params entry to hbpmt\n");
    } else {
        snprintf(response_buffer, sizeof(response_buffer),
                 "CMD_SET_SCHEDULED_MALICIOUS_PARAMS: epoch_employed: %d, corrupt_ratio: %d-%d, corrupt_special_ratio: %d-%d\n",
                 epoch_employed, corrupt_ratio_start, corrupt_ratio_end, corrupt_special_ratio_start,
                 corrupt_special_ratio_end);
    }
    return send_reply(response_buffer, info);
}

int netlink_set_min_ack_for_rtt_estimation(struct sk_buff *request, struct genl_info *info){
    char receive_buffer[MAX_NETLINK_MESSAGE_SIZE];
    char response_buffer[1024];
    struct net *current_ns = sock_net(request->sk);
    int min_ack_for_rtt_estimation;
    {
        int err = recv_message_copy(info, receive_buffer, sizeof(receive_buffer));
        if (err)
            return err;
    }
    min_ack_for_rtt_estimation = (int) (simple_strtol(receive_buffer, NULL, 10));
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    pvs->sec_path_mab_settings->min_ack_for_rtt_estimation = min_ack_for_rtt_estimation;
    snprintf(response_buffer, sizeof(response_buffer), "CMD_SET_MIN_ACK_FOR_RTT_ESTIMATION: %d", min_ack_for_rtt_estimation);
    return send_reply(response_buffer, info);
}