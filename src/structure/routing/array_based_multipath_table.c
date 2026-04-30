#include "structure/header/atlas_segment.h"
#include "structure/routing/array_based_multipath_table.h"
#include "tools/tools.h"
#include "structure/namespace/namespace.h"
#include "structure/routing/table_common.h"

/**
 * 进行 array based multipath table 的初始化
 * @param number_of_destinations 目的节点的数量
 * @return
 */
struct ArrayBasedMultipathTable *init_abpt(int number_of_destinations, int bucket_count, int multipath_routing_type, int number_of_relationships, int number_of_paths) {
    int array_size = number_of_destinations + 1;
    // 分配内存
    struct ArrayBasedMultipathTable *abpt = (struct ArrayBasedMultipathTable *) kmalloc(
            sizeof(struct ArrayBasedMultipathTable), GFP_KERNEL);

    abpt->packet_send_count = 0;

    // 设置路由条目的总数量
    abpt->routing_entries_count = 0;

    abpt->segments_count = 0;

    // 设置路由类型
    abpt->routing_type = multipath_routing_type;

    // 设置路由条数
    abpt->array_size = array_size;

    // 进行 Output_segments 的初始化
    // -------------------------------------------------------------------------------
    if (number_of_relationships > 0) {
        abpt->number_of_interface_to_path_mappings = number_of_relationships;
        abpt->output_interface_to_path_mappings = (struct OutputInterfaceToPathsMapping**)(kmalloc(sizeof(struct OutputInterfaceToPathsMapping*) * abpt->number_of_interface_to_path_mappings, GFP_KERNEL));
        abpt->interface_to_path_mapping_index = 0;
        int i;
        for (i = 0; i < abpt->number_of_interface_to_path_mappings; i++) {
            abpt->output_interface_to_path_mappings[i] = NULL;
        }
    } else {
        abpt->number_of_interface_to_path_mappings = 0;
        abpt->output_interface_to_path_mappings = NULL;
        abpt->interface_to_path_mapping_index = 0;
    }

    abpt->number_of_paths = number_of_paths;
    // -------------------------------------------------------------------------------

    // 进行 multipaths 的初始化
    // ----------------------------------------------------------------------------------------------------------------------------------------------------
    abpt->multipaths = (struct list_head *) kmalloc(sizeof(struct list_head) * array_size, GFP_KERNEL);
    // 将所有的指针置为空
    int index;
    for (index = 0; index < array_size; index++) {
        INIT_LIST_HEAD(&(abpt->multipaths[index]));
    }
    // ----------------------------------------------------------------------------------------------------------------------------------------------------

    // 最大的路径长度置为空
    abpt->max_path_length = -1;

    // 进行 output_link_identifiers 的初始化
    // ----------------------------------------------------------------------------------------------------------------------------------------------------
    abpt->output_link_identifiers = (struct OutputLinkIdentifiers *) kmalloc(sizeof(struct OutputLinkIdentifiers) * array_size, GFP_KERNEL);
    for(index = 0; index < array_size; index++){
        abpt->output_link_identifiers[index].number = 0;
        abpt->output_link_identifiers[index].count = 0; // 发送包的数量
        abpt->output_link_identifiers[index].link_identifiers = NULL;
    }
    // ----------------------------------------------------------------------------------------------------------------------------------------------------

    // 准备初始化一个哈希表
    // ----------------------------------------------------------------------------------------------------------------------------------------------------
    abpt->bucket_count = bucket_count;
    struct hlist_head* head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * bucket_count, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
    }
    // 初始化表头
    for (index = 0; index < bucket_count; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    abpt->bucket_count = bucket_count;
    abpt->bucket_array = head_pointer_list;
    // ----------------------------------------------------------------------------------------------------------------------------------------------------



    // 进行创建结果的返回
    return abpt;
}

void free_abpt(struct ArrayBasedMultipathTable *abpt) {
    // 判断 abrt 是否为 NULL, 如果 NULL == abrt, 则返回
    if (NULL != abpt) {
        // 索引
        int index;
        // 释放 link identifiers
        // ----------------------------------------------------------------------------
        if (NULL != abpt->output_link_identifiers) {
            // 进行所有 link_identifiers 的释放
            for (index = 0; index < abpt->array_size; index++) {
                if (NULL != (abpt->output_link_identifiers[index].link_identifiers)){
                    kfree(abpt->output_link_identifiers[index].link_identifiers);
                }
            }
            kfree(abpt->output_link_identifiers);
            abpt->output_link_identifiers = NULL;
        }
        // ----------------------------------------------------------------------------

        // 释放所有 multipaths
        // ----------------------------------------------------------------------------
        if (NULL != abpt->multipaths) {
            // 遍历所有的路由进行释放
            for (index = 0; index < abpt->array_size; index++) {
                if(abpt->routing_type == ROUTING_TYPE_ATLAS) {
                    // delete_segment_list(&(abpt->multipaths[index]));
                } else if(abpt->routing_type == ROUTING_TYPE_MULTIPATH_SELIR) {
                    delete_paths_list(&(abpt->multipaths[index]));
                } else {
                    printk(KERN_EMERG "unsupported multipath routing type %d\n", abpt->routing_type);
                }
            }
            kfree(abpt->multipaths);
            abpt->multipaths = NULL;
        }
        // ----------------------------------------------------------------------------

        // 释放 output links
        if(NULL != abpt->output_interface_to_path_mappings) {
            for(index = 0; index < abpt->number_of_interface_to_path_mappings; index++){
                if(NULL != abpt->output_interface_to_path_mappings[index]){
                    if (NULL != abpt->output_interface_to_path_mappings[index]->path_ids){
                        kfree(abpt->output_interface_to_path_mappings[index]->path_ids);
                    }
                    if(NULL != abpt->output_interface_to_path_mappings[index]->bit_set) {
                        kfree(abpt->output_interface_to_path_mappings[index]->bit_set);
                    }
                    kfree(abpt->output_interface_to_path_mappings[index]);
                }else {
                    printk(KERN_EMERG " == NULL %d\n", abpt->number_of_interface_to_path_mappings);
                }
            }
        }

        // routing_type == atlas 的时候进行释放
        // ----------------------------------------------------------------------------
        if(ROUTING_TYPE_ATLAS == abpt->routing_type){
            struct hlist_head* hash_bucket = NULL;
            struct AtlasSegment* current_entry  = NULL;
            struct hlist_node* next;
            printk(KERN_EMERG "hash bucket count: %d \n", abpt->bucket_count);
            for (index = 0; index < abpt->bucket_count; index++) {
                hash_bucket = &(abpt->bucket_array[index]);
                // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
                if (NULL == hash_bucket) {
                    LOG_WITH_PREFIX("hash bucket is null");
                    return;
                }
                hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
                    if (NULL != current_entry) {
                        hlist_del(&current_entry->pointer);
                        free_atlas_segment(current_entry);
                    }
                }
            }
        } else if(ROUTING_TYPE_MULTIPATH_SELIR == abpt->routing_type){
            struct hlist_head* hash_bucket = NULL;
            struct RoutingTableEntry* current_entry  = NULL;
            struct hlist_node* next;
            printk(KERN_EMERG "hash bucket count: %d \n", abpt->bucket_count);
            for (index = 0; index < abpt->bucket_count; index++) {
                hash_bucket = &(abpt->bucket_array[index]);
                // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
                if (NULL == hash_bucket) {
                    LOG_WITH_PREFIX("hash bucket is null");
                    return;
                }
                hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
                    if (NULL != current_entry) {
                        hlist_del(&current_entry->pointer);
                        free_rte(current_entry);
                    }
                }
            }
        } else {
            printk(KERN_EMERG "not multipath routing type\n");
        }
        // ----------------------------------------------------------------------------


        // 清空 head_pointer_list 引入的 memory 开销
        if (NULL != abpt->bucket_array) {
            kfree(abpt->bucket_array);
            abpt->bucket_array = NULL;
        }
        // ----------------------------------------------------------------------------

        kfree(abpt);
    } else {
        LOG_WITH_PREFIX("array based multipath table is NULL");
    }
}

/**
 * 进行某个段的删除
 * @param head 段的头
 */
void delete_segment_list(struct list_head* head) {
    struct list_head *pos, *n;
    struct AtlasSegment *atlas_segment;

    // 遍历链表并删除每个节点
    list_for_each_safe(pos, n, head) {
        atlas_segment = list_entry(pos, struct AtlasSegment, list);  // 获取当前节点的数据结构
        if (NULL == atlas_segment){
            LOG_WITH_PREFIX("atlas segment == NULL");
        } else {
            LOG_WITH_PREFIX("atlas segment != NULL");
            list_del(pos);  // 从链表中删除节点
            free_atlas_segment(atlas_segment); // 释放内存并打印
        }
    }
}

/**
 * 进行到某个节点的一系列路径的删除
 * @param head
 */
void delete_paths_list(struct list_head* head){
    struct list_head* pos, *n;
    struct RoutingTableEntry* rte;

    list_for_each_safe(pos, n, head) {
        rte = list_entry(pos, struct RoutingTableEntry, list);  // 获取当前节点的数据结构
        if (NULL == rte){
            LOG_WITH_PREFIX("atlas segment == NULL");
        } else {
            LOG_WITH_PREFIX("atlas segment != NULL");
            list_del(pos);  // 从链表中删除节点
            free_rte(rte); // 释放内存
        }
    }

}

/**
 * 根据目的节点编号找到对应的 segments
 * @param abpt
 * @param destination
 * @return
 */
struct list_head* find_segments_or_paths_in_abpt(struct ArrayBasedMultipathTable *abpt, int destination) {
    return &(abpt->multipaths[destination]);
}

struct AtlasSegment* find_output_interface_in_abpt_for_atlas(struct ArrayBasedMultipathTable* abpt, int node_id, int destination){
    struct AtlasSegment* final_result = NULL;
    // 进行 segment list 的遍历
    struct list_head* segments = find_segments_or_paths_in_abpt(abpt, destination);
    // 进行 count 的递增
    abpt->packet_send_count += 1;
    // 首先获取有出接口的 segments
    struct AtlasSegment** hasInterfaceSegments = kmalloc(sizeof(struct AtlasSegment*) * abpt->segments_count, GFP_KERNEL);
    // 找到存在 ite 的
    int index = 0;
    struct list_head* position;
    list_for_each(position,segments){
        struct AtlasSegment* atlas_segment = list_entry(position, struct AtlasSegment, list);
        if ((atlas_segment->ite != NULL) && atlas_segment->decision_point == node_id){
            hasInterfaceSegments[index++] = atlas_segment;
        }
    }
    if(index == 0){
        final_result = NULL;
    } else {
        int round_robin_selection = abpt->packet_send_count % index;
        final_result =  hasInterfaceSegments[round_robin_selection];
    }

    kfree(hasInterfaceSegments);
    return final_result;
}

struct OutputInterfaceToPathsMapping* find_output_interface_to_paths_mapping(struct ArrayBasedMultipathTable* abpt){
    int round_robin_selection = (abpt->packet_send_count++) % abpt->number_of_interface_to_path_mappings;
    return abpt->output_interface_to_path_mappings[round_robin_selection];
}

struct InterfaceTableEntry* find_output_interface_in_abpt_for_multipath_selir(struct ArrayBasedMultipathTable* abpt, struct ArrayBasedInterfaceTable* abit, int destination){
    // 找到可选的出接口
    struct OutputLinkIdentifiers* output_link_identifiers = &(abpt->output_link_identifiers[destination]);
    // 如果为 0 就直接返回
    if (output_link_identifiers->number == 0){
        printk(KERN_EMERG "number of output link identifiers == 0\n"); // 直接进行回退是防止 mod 0
        return NULL;
    }
    // 将计数递增后进行枚举
    int round_robin_selection = (output_link_identifiers->count++) % output_link_identifiers->number;
    // 进行出链路标识的选择
    int selected_link_identifier = output_link_identifiers->link_identifiers[round_robin_selection];
//    printk(KERN_EMERG "selected link identifier = %d\n", selected_link_identifier);
    // 查找接口表
    int index;
    struct InterfaceTableEntry* output_interface = NULL;
    for(index = 0; index < abit->number_of_interfaces; index++){
        struct InterfaceTableEntry* interface_table_entry_tmp = abit->interfaces[index];
        if(selected_link_identifier == interface_table_entry_tmp->link_identifier){
            output_interface = interface_table_entry_tmp;
            break;
        }
    }
    if (NULL == output_interface){
        return NULL;
    }
    return output_interface;
}


// 哈希表相关内容
u64 calculate_hash_based_on_segment_id(int destination, int segment_id){
    int destination_and_segment_id[2] = {destination, segment_id};
    u32 hash_value = jhash(destination_and_segment_id, sizeof(int) * 2, 1234);
    return hash_value;
}

u64 calculate_hash_based_on_length_of_path(int length_of_path){
    u32 hash_value = jhash(&length_of_path , sizeof(int), 1234);
    return hash_value;
}


struct hlist_head* atlas_get_bucket_in_abpt(struct ArrayBasedMultipathTable* abpt, int destination, int segment_id){
    // 获取 hash truncate
    u64 hash_truncate = calculate_hash_based_on_segment_id(destination,segment_id);
    // 找到对应的桶的索引
    u64 index_of_bucket;
    index_of_bucket = hash_truncate % abpt->bucket_count;
    // 返回对应的桶
    return &abpt->bucket_array[index_of_bucket];
}

struct hlist_head* multipath_selir_get_bucket_in_abpt(struct ArrayBasedMultipathTable* abpt, int length_of_path){
    // 获取 hash truncate
    u64 hash_truncate = calculate_hash_based_on_length_of_path(length_of_path);
    // 找到对应的桶的
    u64 index_of_bucket;
    index_of_bucket = hash_truncate % abpt->bucket_count;
    // 返回对应的桶
    return  &abpt->bucket_array[index_of_bucket];
}

int atlas_segment_equal_judgement(struct AtlasSegment* atlas_segment, int destination, int segment_id){
    if (NULL == atlas_segment){
        return 1;
    }
    if((atlas_segment->destination == destination) && (atlas_segment->id == segment_id)){
        return 0;
    } else {
        return 1;
    }
}

int multipath_selir_routing_entry_equal_judegement(struct RoutingTableEntry* rte, const int* node_identifiers, int length_of_path){
    if(NULL == rte){
        return 1;
    }
    if(rte->path_length != length_of_path){
        return 1;
    }
    int index;
    for(index = 0; index < rte->path_length; index++){
        if(node_identifiers[index] != rte->node_ids[index]){
            return 1;
        } else {
            continue;
        }
    }
    return 0;
}

// 将路由表条目以链表形式进行追加
void add_routing_table_entry_to_abpt_in_chain_format(struct ArrayBasedMultipathTable* abpt, struct RoutingTableEntry* rte){
    // 首先找到对应的 segments
    struct list_head* segments = find_segments_or_paths_in_abpt(abpt, rte->destination_id);
    // 进行初始化
    INIT_LIST_HEAD(&rte->list);
    list_add_tail(&(rte->list), segments);
    // 进行 rte id 的更新
    rte->id = abpt->routing_entries_count; // 编号从1开始, 随着路径数量的增加而增加
    // 进行最大的长度的更新
    if(rte->path_length > abpt->max_path_length) {
        abpt->max_path_length = rte->path_length;
    }
    // 进行总路由条目数量的更新
    abpt->routing_entries_count++;
}

int add_routing_table_entry_to_abpt_in_hash_format(struct ArrayBasedMultipathTable* abpt, struct RoutingTableEntry* rte){
    struct hlist_head* hash_bucket = NULL;
    struct RoutingTableEntry* current_rte = NULL;
    struct hlist_node* next = NULL;
    hash_bucket = multipath_selir_get_bucket_in_abpt(abpt, rte->path_length);
    if(NULL == hash_bucket){
        // 找不到 hash_bucket
        LOG_WITH_PREFIX("cannot find hash bucket");
        free_rte(rte);
        return CANNOT_FIND_BUCKET;
    }
    // 检查一下表项是否已经插入过了
    hlist_for_each_entry_safe(current_rte, next, hash_bucket, pointer){
        if (0 == multipath_selir_routing_entry_equal_judegement(current_rte, rte->node_ids, rte->path_length)) {
            LOG_WITH_PREFIX("already exists rte");
            free_rte(rte);
            return ALREADY_EXISTS;
        }
    }
    // 进行 rte->id 的更新
    rte->id = abpt->routing_entries_count;
    // 进行总路由条数的更新
    abpt->routing_entries_count++;
    // 这个时候我们真的需要创建一个自己的node
    INIT_HLIST_NODE(&rte->pointer);
    hlist_add_head(&rte->pointer, hash_bucket);
    return ADD_SUCCESS;
}

// 以链表的形式进行添加
void atlas_add_entry_to_abpt_in_chain_format(struct ArrayBasedMultipathTable* abpt, struct AtlasSegment* atlas_segment){
    struct list_head* segments =  find_segments_or_paths_in_abpt(abpt, atlas_segment->destination);
    // 将 atlas_segment 追加到 segments 的后面
    INIT_LIST_HEAD(&atlas_segment->list);
    list_add_tail(&(atlas_segment->list), segments);
    abpt->segments_count +=1;
}

// 以哈希形式进行添加
int atlas_add_entry_to_abpt_in_hash_format(struct ArrayBasedMultipathTable* abpt, struct AtlasSegment* atlas_segment){
    struct hlist_head *hash_bucket = NULL;
    struct AtlasSegment *current_atlas_segment = NULL;
    struct hlist_node *next = NULL;
    // 首先找到对应的应该存放的 bucket
    hash_bucket = atlas_get_bucket_in_abpt(abpt, atlas_segment->destination, atlas_segment->id);
    if (NULL == hash_bucket) {
        // 找不到 hash_bucket
        LOG_WITH_PREFIX("cannot find hash bucket");
        free_atlas_segment(atlas_segment);
        return CANNOT_FIND_BUCKET;
    }
    // 检查是否出现了相同的会话表项
    hlist_for_each_entry_safe(current_atlas_segment, next, hash_bucket, pointer) {
        if (0 == atlas_segment_equal_judgement(current_atlas_segment, atlas_segment->destination, atlas_segment->id)) {
            LOG_WITH_PREFIX("already exists atlas segment");
            free_atlas_segment(atlas_segment);
            return ALREADY_EXISTS;
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&atlas_segment->pointer);
    hlist_add_head(&atlas_segment->pointer, hash_bucket);
    return ADD_SUCCESS;
}

struct AtlasSegment* find_atlas_segment_in_abpt(struct ArrayBasedMultipathTable* abpt, int destination, int segment_id){
    struct hlist_head *hash_bucket = NULL;
    struct AtlasSegment *current_entry = NULL;
    struct hlist_node *next;
    hash_bucket = atlas_get_bucket_in_abpt(abpt, destination, segment_id);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == atlas_segment_equal_judgement(current_entry, destination, segment_id)) {
            // 将 atlas segment 进行一份拷贝之后返回
            struct AtlasSegment* atlas_segment = create_copy_of_atlas_segment(current_entry);
            return atlas_segment;
        }
    }
    return NULL;
}

struct RoutingTableEntry* find_rte_in_abpt(struct ArrayBasedMultipathTable* abpt, int* node_identifiers, int length_of_path){
    struct hlist_head* hash_bucket = NULL;
    struct RoutingTableEntry* current_rte = NULL;
    struct hlist_node* next;
    hash_bucket = multipath_selir_get_bucket_in_abpt(abpt, length_of_path);
    if(NULL == hash_bucket){
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_rte, next, hash_bucket, pointer){
        if (0 == multipath_selir_routing_entry_equal_judegement(current_rte, node_identifiers, length_of_path)){
            return current_rte;
        }
    }
    return NULL;
}


struct AtlasSegment* create_copy_of_atlas_segment(struct AtlasSegment* atlas_segment){
    struct AtlasSegment* atlas_segment_copy = (struct AtlasSegment*)kmalloc(sizeof(struct AtlasSegment), GFP_KERNEL);
    atlas_segment_copy->id = atlas_segment->id;
    atlas_segment_copy->destination = atlas_segment->destination;
    atlas_segment_copy->depth = atlas_segment->depth;
    atlas_segment_copy->parent_id = atlas_segment->parent_id;
    atlas_segment_copy->length = atlas_segment->length;
    atlas_segment_copy->array = kmalloc(sizeof(int)*atlas_segment->length, GFP_KERNEL);
    memcpy(atlas_segment_copy->array, atlas_segment->array, sizeof(int) * atlas_segment->length);
    atlas_segment_copy->decision_point = atlas_segment->decision_point;
    atlas_segment_copy->self_position_in_the_segment = atlas_segment->self_position_in_the_segment;
    atlas_segment_copy->ite = atlas_segment->ite;
    return atlas_segment_copy;
}

struct AtlasSegment* intermediate_insert_atlas_segment(char* receive_buffer, struct ArrayBasedMultipathTable* abpt){
    struct net* ns = current->nsproxy->net_ns;
    struct PathValidationStructure* pvs = get_pvs_from_ns(ns);

    // 变量定义
    const char* delimiter = ",";
    struct AtlasSegment* atlas_segment = (struct AtlasSegment*)kmalloc(sizeof(struct AtlasSegment), GFP_KERNEL);
    struct list_head* segments;
    int count = 0;

    // 参数定义
    int segment_id;
    int destination;
    int depth;
    int parent_id;
    int length_of_path;
    int node_identifier;

    // 进行参数的解析
    while (true){
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimiter);
        // 如果为空就进行 break
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            if (count == 0){
                segment_id =  (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->id = segment_id;
            } else if (count == 1){
                destination = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->destination = destination;
                // 根据 destination 查找对应的 segments
                segments = find_segments_or_paths_in_abpt(abpt, destination);
            } else if (count == 2){
                depth = (int)(simple_strtol(variable_in_str, NULL,10));
                atlas_segment->depth = depth;
            } else if (count == 3){
                parent_id = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->parent_id = parent_id;
            } else if (count == 4){
                length_of_path = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->length = length_of_path;
                atlas_segment->array = kmalloc(sizeof(int)*length_of_path, GFP_KERNEL);
            }
            else {
                node_identifier = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->array[count-5] = node_identifier;
            }
        }
        count += 1;
    }

    // 设置 segment 的决策节点为源节点
    atlas_segment->decision_point = atlas_segment->array[0];

    // 进行 atlasSegment 之中的 array 的遍历, 从而获取出接口
    // -------------------------------------------------------------------------------------------------------
    int index;
    for(index = 0; index< atlas_segment->length ;index++){
        if (index != (atlas_segment->length-1)){
            int current_node = atlas_segment->array[index];
            if(current_node == pvs->node_id){
                int next_node_index = index + 1;
                int next_node = atlas_segment->array[next_node_index];
                // 进行接口表的遍历
                // -------------------------------------------------------------------------------------------
                struct InterfaceTableEntry* ite = NULL;
                int interface_index;
                for(interface_index = 0; interface_index < pvs->abit->number_of_interfaces; interface_index++){
                    struct InterfaceTableEntry* tmp = pvs->abit->interfaces[interface_index];
                    if(tmp->target_node_id == next_node){
                        ite = tmp;
                        break;
                    }
                }

                atlas_segment->ite = ite;
                if((pvs->node_id == 4) && (ite == NULL)){
                    printk(KERN_EMERG "segment %d has no ite\n", atlas_segment->id);
                } else if((pvs->node_id == 4) && (ite != NULL)){
                    printk(KERN_EMERG "segment %d has interface link identifier %d\n", atlas_segment->id, ite->link_identifier);
                }
                // -------------------------------------------------------------------------------------------
            }
        }
    }
    // -------------------------------------------------------------------------------------------------------

    // 遍历一遍寻找自己所处的位置
    int position = -1; // 只有源会出现 -1 的情况
    for(index = 0; index < atlas_segment->length; index++){
        if(pvs->node_id == atlas_segment->array[index]){
            position = index;
            break;
        }
    }
    // 1->2->3->4 (2 的 position 是 1, 但是实际上是第一个 opv)
    atlas_segment->self_position_in_the_segment = position;

    printk(KERN_EMERG "atlas_segment self position %d pvs->node_id = %d \n", atlas_segment->self_position_in_the_segment, pvs->node_id);

    // 同样需要添加到主表之中
    atlas_add_entry_to_abpt_in_chain_format(pvs->abpt, atlas_segment);

    // 添加到哈希表之中
    atlas_add_entry_to_abpt_in_hash_format(pvs->abpt, atlas_segment);

    return atlas_segment;
}

struct AtlasSegment* source_insert_atlas_segment(char* receive_buffer, struct ArrayBasedMultipathTable* abpt){
    struct net* ns = current->nsproxy->net_ns;

    // 变量定义
    const char* delimiter = ",";
    struct PathValidationStructure* pvs = get_pvs_from_ns(ns);
    struct AtlasSegment* atlas_segment = (struct AtlasSegment*)kmalloc(sizeof(struct AtlasSegment), GFP_KERNEL);
    int count = 0;

    // 参数定义
    int segment_id;
    int destination;
    int depth;
    int parent_id;
    int length_of_path;
    int node_identifier;

    // 进行参数的解析
    while (true){
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimiter);
        // 如果为空就进行 break
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            if (count == 0){
                segment_id =  (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->id = segment_id;
            } else if (count == 1){
                destination = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->destination = destination;
                // 根据 destination 查找对应的 segments
            } else if (count == 2){
                depth = (int)(simple_strtol(variable_in_str, NULL,10));
                atlas_segment->depth = depth;
            } else if (count == 3){
                parent_id = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->parent_id = parent_id;
            } else if (count == 4){
                length_of_path = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->length = length_of_path;
                atlas_segment->array = kmalloc(sizeof(int)*length_of_path, GFP_KERNEL);
            } else {
                node_identifier = (int)(simple_strtol(variable_in_str, NULL, 10));
                atlas_segment->array[count-5] = node_identifier;
            }
        }
        count += 1;
    }

    // 设置 segment 的决策节点为源节点
    atlas_segment->decision_point = atlas_segment->array[0];

    // 进行 atlasSegment 之中的 array 的遍历, 从而获取出接口
    // -------------------------------------------------------------------------------------------------------
    int index;
    for(index = 0; index< atlas_segment->length ;index++){
        if (index != (atlas_segment->length-1)){
            int current_node = atlas_segment->array[index];
            if(current_node == pvs->node_id){
                int next_node_index = index + 1;
                int next_node = atlas_segment->array[next_node_index];
                // 进行接口表的遍历
                // -------------------------------------------------------------------------------------------
                struct InterfaceTableEntry* ite = NULL;
                int interface_index;
                for(interface_index = 0; interface_index < pvs->abit->number_of_interfaces; interface_index++){
                    struct InterfaceTableEntry* tmp = pvs->abit->interfaces[interface_index];
                    if(tmp->target_node_id == next_node){
                        ite = tmp;
                        break;
                    }
                }
                atlas_segment->ite = ite;
                // -------------------------------------------------------------------------------------------
            }
        }
    }
    // -------------------------------------------------------------------------------------------------------


    // 进行添加
    atlas_add_entry_to_abpt_in_chain_format(abpt, atlas_segment);

    // 将创建完成的结果进行返回
    return atlas_segment;
}