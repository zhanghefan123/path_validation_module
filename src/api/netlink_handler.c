#include "api/netlink_router.h"
#include "api/netlink_handler.h"
#include "structure/path_validation_structure.h"
#include "structure/namespace/namespace.h"
#include "structure/routing/routing_table_entry.h"
#include "structure/routing/variables.h"
#include "tools/tools.h"
#include <linux/inet.h>
/**
 * 提取 netlink 消息
 * @param info generate netlink 消息
 * @return 解析得到的消息
 */
char *recv_message(struct genl_info *info) {
    // 1. 判断 generate netlink info 是否为 NULL
    if (NULL == info) {
        return "";
    }
    // 2. 判断是否存在数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return "";
    }
    // 3. 进行消息的返回
    return nla_data(info->attrs[EXMPL_NLA_DATA]);
}

/**
 * 发送响应消息
 * @param response_buffer
 */
int send_reply(char *response_buffer, struct genl_info *info) {
    struct sk_buff *reply_message;       // 相应消息
    void *message_header;                // 消息头部
    // 1. 进行消息的内存分配
    reply_message = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (NULL == reply_message) {
        return -ENOMEM;
    }
    // 2. 进行消息头的内存分配
    message_header = genlmsg_put_reply(reply_message, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (NULL == message_header) {
        return -ENOMEM;
    }
    // 3. 填充 EXMPL_NLA_DATA 部分
    if (0 != nla_put_string(reply_message, EXMPL_NLA_DATA, response_buffer)) {
        return -EINVAL;
    }
    // 4. 填充 EXMPL_NLA_LEN 部分
    if (0 != nla_put_u32(reply_message, EXMPL_NLA_LEN, strlen(response_buffer))) {
        return -EINVAL;
    }
    // 5. 结束响应消息的构建
    genlmsg_end(reply_message, message_header);
    // 6. 进行消息的返回
    if (0 != genlmsg_reply(reply_message, info)) {
        return -EINVAL;
    }
    return 0;
}

/**
 * 处理回显命令
 * @param request
 * @param info
 * @return
 */
int netlink_echo_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;                // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    // -----------------------------------------------------------------

    // 2. 准备进行消息的处理
    // -----------------------------------------------------------------
    receive_buffer = recv_message(info);
    if (0 == strcmp("", receive_buffer)) {
        return -EINVAL;
    }
    snprintf(response_buffer, sizeof(response_buffer), "%s", receive_buffer);
    // -----------------------------------------------------------------

    // 3. 准备进行消息的返回
    // -----------------------------------------------------------------
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 进行 id 的设置
 * @param request
 * @param info
 * @return
 */
int netlink_set_node_id_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    struct net *current_ns = sock_net(request->sk);
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int node_id; // 节点 id
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: number_of_routes, number_of_interfaces
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    node_id = (int) (simple_strtol(receive_buffer, NULL, 10));
    // 3.2 从 current_ns 之中获取 path_validation_structure
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 3.3 创建 path validation structure
    pvs->node_id = node_id;
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer), "node id: %d", node_id);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 处理初始化命令
 * @param request
 * @param info
 * @return
 */
int netlink_init_routing_and_forwarding_table_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimiter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int routing_table_type; // 路由表类型
    int number_of_routes_or_buckets;   // 路由条数或者桶数
    int number_of_interfaces; // 接口数量
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: routing_table_type, number_of_routes, number_of_interfaces
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimiter);
        // 如果为空就进行 break
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                routing_table_type = variable_in_integer;
            } else if (count == 1) {
                number_of_routes_or_buckets = variable_in_integer;
            } else if (count == 2) {
                number_of_interfaces = variable_in_integer;
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 3.2 从 current_ns 之中获取 path_validation_structure
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 3.3 创建 path validation structure
    initialize_routing_and_forwarding_table(pvs,
                                            routing_table_type,
                                            number_of_routes_or_buckets,
                                            number_of_interfaces);
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    if (routing_table_type == 1) {
        snprintf(response_buffer, sizeof(response_buffer), "number_of_routes: %d, number_of_interfaces: %d",
                 number_of_routes_or_buckets, number_of_interfaces);
    } else if (routing_table_type == 2) {
        snprintf(response_buffer, sizeof(response_buffer), "number_of_buckets: %d, number_of_interfaces: %d",
                 number_of_routes_or_buckets, number_of_interfaces);
    } else {
        snprintf(response_buffer, sizeof(response_buffer), "unknown routing table type");
    }
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}


/**
 * 初始化 selir 数据结构
 * @param request
 * @param info
 * @return
 */
int netlink_init_selir(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimiter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int pvf_effective_bits; // 单位为 bit (实际的使用的位数)
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: pvf_effective_bits
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimiter);
        // 如果为空就进行 break
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                pvf_effective_bits = variable_in_integer;
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 3.2 拿到 pvs
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if (NULL == pvs) {
        return -EINVAL;
    }

    // 3.3 设置 pvs 之中的 selir_info
    pvs->selir_info->pvf_effective_bits = pvf_effective_bits;
    pvs->selir_info->pvf_effective_bytes = (pvf_effective_bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;

    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer),
             "selir pvf_effective_bits: %d, pvf_effective_bytes: %d",
             pvs->selir_info->pvf_effective_bits,
             pvs->selir_info->pvf_effective_bytes);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 处理初始化命令
 * @param request
 * @param info
 * @return
 */
int netlink_init_bloom_filter_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimeter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int bf_effective_bits; // 单位为 bit (实际的使用的位数)
    int hash_seed; // 哈希种子
    int number_of_hash_functions; // 哈希函数的个数
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: bf_effective_bits (在 LiR 之中就是 bf 所占的 bit 数量), pvf_effective_bytes (仅在 selir 之中有效), hash_seed, number_of_hash_functions
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimeter);
        // 如果为空就进行 break
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
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 3.2 创建 bloom filter
    struct BloomFilter *bloom_filter = init_bloom_filter(bf_effective_bits,
                                                         hash_seed,
                                                         number_of_hash_functions);
    // 3.3 设置到 namespace 之中
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if (NULL == pvs) {
        return -EINVAL;
    } else {
        pvs->bloom_filter = bloom_filter;
    }
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer),
             "effective_bits: %d, hash_seed: %d, number_of_hash_functions: %d",
             bf_effective_bits, hash_seed, number_of_hash_functions);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 处理接口表条目的插入命令
 * @param request
 * @param info
 * @return
 */
int netlink_insert_routing_table_entry_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimeter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    struct BloomFilter *bf = pvs->bloom_filter;
    struct RoutingTableEntry *rte = init_routing_table_entry((int) (bf->bf_effective_bytes));
    struct InterfaceTableEntry *first_interface = NULL;
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int source_id; // 源索引
    int destination_id; // 目的索引
    int path_length; // 路径长度
    int first_link_identifier; // 第一个链路标识
    int link_identifier_index = 0; // 链路标识索引
    int node_index = 0; // 节点索引
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 测试拓扑: a -----1-----> b -----2-----> c
    // 链路标识: [1,2]
    // 节点标识: [b,c]
    // 消息格式: source_id, destination_id, length_of_path, link_id1, node_id1, link_id2, node_id2, ...
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimeter);
        // 如果为空就进行 break
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
                rte->link_identifiers = (int *) kmalloc(sizeof(int) * path_length, GFP_KERNEL);
                rte->node_ids = (int *) kmalloc(sizeof(int) * path_length, GFP_KERNEL);
            } else {
                if (count == 3) {
                    first_link_identifier = variable_in_integer;
                    first_interface = find_ite_in_abit(pvs->abit, first_link_identifier);
                    rte->output_interface = first_interface;
                    rte->link_identifiers[link_identifier_index++] = variable_in_integer;
                    // 第一个 link identifier 不用 push 到布隆过滤器之中
                } else if (count % 2 == 0) { // node id
                    rte->node_ids[node_index++] = variable_in_integer;
                } else if (count % 2 == 1) { // link identifier
                    rte->link_identifiers[link_identifier_index++] = variable_in_integer;
                    push_element_into_bloom_filter(bf, &variable_in_integer, sizeof(variable_in_integer));
                }
            }
        }
        count += 1;
    }
    // 3.2 进行布隆过滤器的拷贝, 拷贝到相应的位置去
    memcpy(rte->bitset, bf->bitset, sizeof(unsigned char) * bf->bf_effective_bytes);
    // 3.3 结束的时候进行布隆过滤器的重置
    reset_bloom_filter(bf);
    // 3.4 放到路由表之中
    // 3.4.1 判断使用的路由表的类型
    if (ARRAY_BASED_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        add_entry_to_abrt(pvs->abrt, rte);
    } else if (HASH_BASED_ROUTING_TABLE_TYPE == pvs->routing_table_type) {
        add_entry_to_hbrt(pvs->hbrt, rte);
    }
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer),
             "source_id: %d, destination_id: %d, path_length: %d, link_identifier_index: %d, node_index: %d",
             source_id, destination_id, path_length, link_identifier_index, node_index);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 处理路由条目的插入命令
 * @param request
 * @param info
 * @return
 */
int netlink_insert_interface_table_entry_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimiter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);  // 获取当前网络命名空间
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);  // 获取 pvs
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int index; // 索引
    int link_identifier; // 链路标识
    int ifindex; // 接口索引
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: index, link_identifier, ifindex
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    int variable_in_integer;
    __be32 peer_ip_address;
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimiter);
        // 如果为空就进行 break
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
            } else if (count == 3){
                peer_ip_address = in_aton(variable_in_str);
                printk(KERN_EMERG "peer_interface_address_str: %s\n", variable_in_str);
                printk(KERN_EMERG "peer_interface_address: %pI4\n", &peer_ip_address);
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 3.2 创建接口表项
    struct InterfaceTableEntry *ite = init_ite(index, (int) (pvs->bloom_filter->bf_effective_bytes));
    push_element_into_bloom_filter(pvs->bloom_filter, &link_identifier, sizeof(link_identifier));
    ite->link_identifier = link_identifier;
    ite->interface = dev_get_by_index(current_ns, ifindex);
    ite->peer_ip_address = peer_ip_address;
    dev_put(ite->interface);
    memcpy(ite->bitset, pvs->bloom_filter->bitset, pvs->bloom_filter->bf_effective_bytes);
    reset_bloom_filter(pvs->bloom_filter);
    // 3.3 将接口表项添加到接口表之中
    add_ite_to_abit(pvs->abit, ite);
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer),
             "index: %d, link_identifier: %d, ifindex: %d, ifname: %s",
             index, link_identifier, ifindex, pvs->abit->interfaces[index]->interface->name);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

