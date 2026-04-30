#include "structure/header/atlas_validation_field.h"
#include "structure/header/atlas_segment.h"
#include "structure/header/atlas_header_list.h"


static unsigned char* init_pvf(struct shash_desc* hmac_api, unsigned char* static_fields_hash, char* destination_key){
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    static_fields_hash,
                                                    HASH_LENGTH, // 注意其他的数据接收着也只能拿到 HASH_LENGTH 16 而不是完整的 20 bytes.
                                                    (unsigned char*)destination_key,
                                                    (int)strlen(destination_key));
    return pvf_hmac_result;
}

static unsigned char* update_pvf(struct shash_desc* hmac_api, unsigned char* previous_pvf, char* key){
    unsigned char *pvf_hmac_result = calculate_hmac(hmac_api,
                                                    previous_pvf,
                                                    PVF_LENGTH, // 注意其他的数据接收着也只能拿到 HASH_LENGTH 16 而不是完整的 20 bytes.
                                                    (unsigned char*)key,
                                                    (int)strlen(key));
    return pvf_hmac_result;
}

static unsigned char* calculate_opv(struct shash_desc* hmac_api, unsigned char* pvf_hmac_result, unsigned char* static_fields_hash, int previous_node_index, char* key){
    // 进行拼接的构建
    unsigned char combination[PVF_LENGTH + HASH_LENGTH + 4 + TIMESTAMP_LENGTH];
    memcpy(combination, pvf_hmac_result, PVF_LENGTH);
    memcpy(combination+ PVF_LENGTH, static_fields_hash, HASH_LENGTH);
    memcpy(combination+ PVF_LENGTH + HASH_LENGTH, &previous_node_index, sizeof(int));
    *((time64_t *) (combination + PVF_LENGTH + HASH_LENGTH + sizeof(int))) = 1; // 这里的时间戳设置为固定的, 为了简化
    // 拿到节点的 key
    unsigned char* opv = calculate_hmac(hmac_api,
                                        combination,
                                        PVF_LENGTH + HASH_LENGTH + 4 + TIMESTAMP_LENGTH,
                                        (unsigned char*) key,
                                        (int)strlen(key));
    return opv;
}


// 从 segment list 生成 header list
struct HeaderList* create_header_list_from_segment(struct AtlasSegment* segment, unsigned char* static_fields_hash, struct shash_desc* hmac_api, int* mac_count){
    // 1. 为 header_list 进行内存的分配
    struct HeaderList* header_list = (struct HeaderList*)kmalloc(sizeof(struct HeaderList), GFP_KERNEL);
    // 2. header_list 的基本字段初始化
    header_list->source_node_index = segment->array[0];
    header_list->destination_node_index = segment->array[segment->length-1];
    header_list->depth = segment->depth;
    header_list->start_tag = segment->id;
    header_list->end_tag = segment->id;
    header_list->parent_id = segment->parent_id;

    // 3. validation field list 分配内存并初始化
    header_list->validation_field_list = (struct list_head*) kmalloc(sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(header_list->validation_field_list);
    // 4.填充 validation field list
    // --------------------------------------------------------------------------------------------------------------------------------------------
    int index;
    unsigned char* pvf_result = NULL;
    // 4.1 进行 start tag 的添加
    // --------------------------------------------
    struct ValidationField* start_tag = (struct ValidationField*)kmalloc(sizeof (struct ValidationField), GFP_KERNEL);
    start_tag->type = VALIDATION_FIELD_TYPE_TAG;
    start_tag->segment = segment->id;
    start_tag->removed = 0;
    start_tag->validation_node_index = -1;
    snprintf(start_tag->validation_field_desc, sizeof(start_tag->validation_field_desc), "[tag-%d]", start_tag->segment);
    INIT_LIST_HEAD(&(start_tag->list));
    list_add_tail(&(start_tag->list), header_list->validation_field_list);
    // --------------------------------------------
    for(index =0; index < segment->length; index++){
        // printk(KERN_EMERG "segment->length = %d\n", segment->length);
        if(index == 0){
            // 4.2 进行 pvf 的计算
            struct ValidationField* validation_field = (struct ValidationField*)kmalloc(sizeof (struct ValidationField), GFP_KERNEL);
            validation_field->validation_node_index = segment->array[index];
            validation_field->type = VALIDATION_FIELD_TYPE_PVF;
            validation_field->segment = segment->id;
            // 进行描述
            snprintf(validation_field->validation_field_desc, sizeof(validation_field->validation_field_desc), "Seg_%d[PVF]", segment->id);
            // ---------------------------------- 进行 pvf 的构建 ----------------------------------
            char dest_key[20];
            int segment_destination_node = segment->array[segment->length-1];
            snprintf(dest_key, sizeof(dest_key), "key-%d", segment_destination_node);
            pvf_result = init_pvf(hmac_api, static_fields_hash, dest_key);
            memcpy(validation_field->validation_field, pvf_result, PVF_LENGTH);
            // 这里不立即进行释放是因为后面还需要进行使用
            // ---------------------------------- 进行 pvf 的构建 ----------------------------------

            *mac_count = *mac_count + 1;

            // 将节点进行初始化
            INIT_LIST_HEAD(&(validation_field->list));
            // 将节点添加到末尾
            list_add_tail(&(validation_field->list), (header_list->validation_field_list));
        } else {
            // 4.3 进行 opv 的计算
            struct ValidationField* validation_field = (struct ValidationField*)kmalloc(sizeof (struct ValidationField), GFP_KERNEL);
            validation_field->type = VALIDATION_FIELD_TYPE_OPV;
            validation_field->validation_node_index = segment->array[index];
            validation_field->segment = segment->id;
            snprintf(validation_field->validation_field_desc, sizeof(validation_field->validation_field_desc), "Seg_%d[OPV_%d]", segment->id, segment->array[index]);
            // ---------------------------------- 进行 opv 的构建 ----------------------------------
            char intermediate_key[20];
            snprintf(intermediate_key, sizeof(intermediate_key), "key-%d", segment->array[index]);
            unsigned char* opv = calculate_opv(hmac_api, pvf_result, static_fields_hash, segment->array[index-1], intermediate_key);
            memcpy(validation_field->validation_field, opv, OPV_LENGTH);
            kfree(opv); // 进行 opv 的释放

            *mac_count = *mac_count + 1;
            // ---------------------------------- 进行 opv 的构建 ----------------------------------
            // ---------------------------------- 进行 pvf 的更新 ----------------------------------
            if(index != (segment->length-1)){
                unsigned char* pvf_tmp = update_pvf(hmac_api, pvf_result, intermediate_key);
                *mac_count = *mac_count + 1;
                kfree(pvf_result);
                pvf_result = pvf_tmp;
            } else {
                kfree(pvf_result);
            }
            // ---------------------------------- 进行 pvf 的更新 ----------------------------------
            // 将节点进行初始化
            INIT_LIST_HEAD(&(validation_field->list));
            // 将节点添加到末尾
            list_add_tail(&(validation_field->list), (header_list->validation_field_list));
        }
    }
    // 进行 END tag 的添加
    // --------------------------------------------
    struct ValidationField* end_tag = (struct ValidationField*)kmalloc(sizeof (struct ValidationField), GFP_KERNEL);
    end_tag->type = VALIDATION_FIELD_TYPE_END_TAG;
    end_tag->segment = segment->id;
    end_tag->validation_node_index = -1;
    end_tag->removed = 0;
    snprintf(end_tag->validation_field_desc, sizeof(end_tag->validation_field_desc), "[endtag-%d]", end_tag->segment);
    INIT_LIST_HEAD(&(end_tag->list));
    list_add_tail(&(end_tag->list), header_list->validation_field_list);
    // --------------------------------------------
    // --------------------------------------------------------------------------------------------------------------------------------------------
    return header_list;
}

void print_header_list(struct HeaderList* header_list){

    printk(KERN_CONT "source: %d, depth: %d, ", header_list->source_node_index, header_list->depth);
    struct ValidationField* validation_field;
    struct list_head* validation_position;
    list_for_each(validation_position, header_list->validation_field_list){
        validation_field = list_entry(validation_position, struct ValidationField, list);
        printk(KERN_CONT "%s,", validation_field->validation_field_desc);
    }
    printk(KERN_EMERG "\n");

}

void print_validation_list(struct list_head* validation_list){
    struct ValidationField* validation_field;
    struct list_head* validation_position;
    list_for_each(validation_position, validation_list){
        validation_field = list_entry(validation_position, struct ValidationField, list);
        printk(KERN_CONT "%s,", validation_field->validation_field_desc);
    }
}

void print_all_header_lists(struct list_head* all_header_list){
    LOG_WITH_EDGE("header list");
    struct list_head* position;

    struct HeaderList* header_list;

    list_for_each(position, all_header_list){
        header_list = list_entry(position, struct HeaderList, list);
        print_header_list(header_list);
    }
    LOG_WITH_EDGE("header list");
}

struct list_head* integrate(struct list_head* all_headers_lists, int depth){
    // 如果深度 <= 0 直接进行返回，因为深度为0 的只有一条
    if(depth <= 0){
        return all_headers_lists;
    }

    // first_layer 对应于深度最深的 (由于需要动态删除, 所以结合 list_for_each_entry_safe 进行使用)
    struct HeaderList* header_list_first_layer;
    struct HeaderList* header_list_first_layer_tmp;
    // second layer 对应于深度第二深的
    struct HeaderList* header_list_second_layer;
    struct list_head* position_second_layer;

    // 1. 进行第一层的遍历 (深度最深的)
    list_for_each_entry_safe(header_list_first_layer, header_list_first_layer_tmp,  all_headers_lists, list){
        // 拿到深度最深的节点
        if(depth == header_list_first_layer->depth){
            // printk(KERN_CONT "first layer: ");
            // print_header_list(header_list_first_layer);
            // 2. 进行第二层的遍历 (深度第二深的)
            list_for_each(position_second_layer, all_headers_lists){
                // 拿到对应的 header list
                header_list_second_layer = list_entry(position_second_layer, struct HeaderList, list);
                // 如果深度为第二深的
                if ((depth-1) == header_list_second_layer->depth){
                    // printk(KERN_CONT "second layer: ");
                    // print_header_list(header_list_second_layer);
                    bool should_remove_second_layer_validation_list = false;
                    // 这里一定需要使用 temp_storage, 因为 find_and_insert 会改变 header_list_second_layer->validation_field_list 的指向 (会指向一个全新的链表)
                    // 这里的 temp_storage 代表要被插入的
                    struct list_head* temp_storage = (header_list_second_layer->validation_field_list);
                    // 判断是否需要进行插入
                    struct ValidationField* insert_after_validation_field = judge_should_insert(header_list_first_layer, header_list_second_layer);
                    if(insert_after_validation_field != NULL){
                        // printk(KERN_EMERG "insert after validation field belong segment = %d\n", insert_after_validation_field->segment);
                        find_and_insert(header_list_first_layer, header_list_second_layer, insert_after_validation_field);
                        should_remove_second_layer_validation_list = true;
                    }
                    if(should_remove_second_layer_validation_list){
                        remove_validation_field_list(temp_storage);
                    }
                }
            }
        }
    }

    // 进行递归
    return integrate(all_headers_lists, depth-1);
}

/*
c 13 09:49:44 zhf-virtual-machine kernel: [46693.139466] source: 1, depth: 0, [tag-1],Seg_1[PVF],Seg_1[OPV_2],Seg_1[OPV_3],Seg_1[OPV_10],Seg_1[OPV_11],Seg_1[OPV_12],[endtag-1],
Dec 13 09:49:44 zhf-virtual-machine kernel: [46693.139479]
Dec 13 09:49:44 zhf-virtual-machine kernel: [46693.139482] source: 3, depth: 1, [tag-2],Seg_2[PVF],Seg_2[OPV_4],Seg_2[OPV_5],Seg_2[OPV_10],[endtag-2],
Dec 13 09:49:44 zhf-virtual-machine kernel: [46693.139492]
Dec 13 09:49:44 zhf-virtual-machine kernel: [46693.139494] source: 3, depth: 1, [tag-3],Seg_3[PVF],Seg_3[OPV_6],Seg_3[OPV_7],Seg_3[OPV_9],Seg_3[OPV_10],[endtag-3],

 */
// from -> to
struct ValidationField* judge_should_insert(struct HeaderList* header_list_with_depth, struct HeaderList* header_list_with_depth_minus_one){
    struct list_head* position;
    struct ValidationField* validation_field;
    struct ValidationField* insert_after_validation_field = NULL;
    bool with_same_source = false;
    bool has_destination = false;
    bool is_parent = false;
    list_for_each(position, header_list_with_depth_minus_one->validation_field_list){
        validation_field = list_entry(position, struct ValidationField, list);
        bool belong_to_original_validation_field = validation_field->segment == header_list_with_depth_minus_one->start_tag;
        if(!belong_to_original_validation_field){
            continue;
        }
        // virtual link start
        if((header_list_with_depth->source_node_index == validation_field->validation_node_index) && (validation_field->type == VALIDATION_FIELD_TYPE_PVF || validation_field->type == VALIDATION_FIELD_TYPE_OPV) ){
            with_same_source = true;
            insert_after_validation_field = validation_field;
        }
        // virtual link end
        if((header_list_with_depth->destination_node_index == validation_field->validation_node_index) && (validation_field->type == VALIDATION_FIELD_TYPE_PVF || validation_field->type == VALIDATION_FIELD_TYPE_OPV) ){
            has_destination = true;
        }
        // should be parent
        if (header_list_with_depth->parent_id == header_list_with_depth_minus_one->start_tag){
            is_parent = true;
        }
    }
    if(with_same_source && has_destination && is_parent){
        return insert_after_validation_field;
    } else {
        return NULL;
    }
}

void find_and_insert(struct HeaderList* from, struct HeaderList* to, struct ValidationField* validation_field){
    if (from == NULL || to == NULL || validation_field == NULL) {
        LOG_WITH_PREFIX("incoming param NULL");
        return;
    }
    // 最终结果
    struct list_head* final_list = (struct list_head*)kmalloc(sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(final_list);

    // 第一层遍历
    struct list_head* position_first_layer;
    struct ValidationField* validation_field_first_layer;
    // 第二层遍历
    struct list_head* position_second_layer;
    struct ValidationField* validation_field_second_layer;
    struct ValidationField* copy;

    bool already_inserted = false;

    // 遍历  1->2->3->10->11->12 全部遍历, 发现 segment 2 (depth1) 3->4->5->10 的 source 和 3 匹配, 因此进行插入
    // 然后遍历发现 segment 3 (depth1) 3->6->7->9->10 的 source 和 3 匹配, 因此进行插入
    list_for_each(position_first_layer, (to->validation_field_list)){
        validation_field_first_layer = list_entry(position_first_layer, struct ValidationField, list);
        // 如果不等于的话直接插入, 如果相等的话插入到后面 (这句话后续一次也没执行)
        if ((validation_field_first_layer->validation_node_index == validation_field->validation_node_index) && (validation_field_first_layer->segment==validation_field->segment)){
            // 如果等于的话直接插入, 并且在后面添加上 from 之中的所有内容
            copy = create_validation_field_copy(validation_field_first_layer);
            list_add_tail(&(copy->list), final_list);
            // 只进行一次插入
            if(!already_inserted){
                list_for_each(position_second_layer, (from->validation_field_list)){
                    validation_field_second_layer = list_entry(position_second_layer, struct ValidationField, list);
                    copy = create_validation_field_copy(validation_field_second_layer);
                    list_add_tail(&(copy->list), final_list);
                }
                already_inserted = true;
            }
        } else{ // 如果不等的话直接插入
            copy = create_validation_field_copy(validation_field_first_layer);
            list_add_tail(&(copy->list), final_list);
        }
    }




//    LOG_WITH_EDGE("from");
//    print_header_list(from);
//    LOG_WITH_EDGE("from");

//    LOG_WITH_EDGE("to");
//    print_header_list(to);
//    LOG_WITH_EDGE("to");

    // 重置 validation_field_list
    to->validation_field_list = final_list;


    // 进行更新后的 to 的打印
//    LOG_WITH_EDGE("after to");
//    print_header_list(to);
//    LOG_WITH_EDGE("after to");
}

void remove_validation_field_list(struct list_head* validation_field_list){
    struct ValidationField* entry, *tmp;
    list_for_each_entry_safe(entry, tmp, validation_field_list, list){
        if(NULL != entry){
            list_del(&entry->list);
            kfree(entry);
        } else {
            printk(KERN_EMERG "NULL\n");
        }
    }
}


/**
 * 将 delete_header_list 从 all_header_list 之中删除
 * @param all_header_list
 * @param delete_header_list
 */
void remove_header_list(struct list_head* all_header_list, struct HeaderList* delete_header_list){
    struct HeaderList *entry, *tmp;
    // 使用 list_for_each_safe 进行遍历
    list_for_each_entry_safe(entry, tmp, all_header_list, list){
        if(entry->start_tag == delete_header_list->start_tag){
            list_del(&entry->list);
            free_header_list(entry);
        }
    }
}

void remove_all_header_list(struct list_head* all_header_list){
    struct HeaderList *entry, *tmp;
    // 使用 list_for_each_safe 进行遍历
    list_for_each_entry_safe(entry, tmp, all_header_list, list){
        if(entry != NULL){
            list_del(&entry->list);
            free_header_list(entry);
        } else {
            printk(KERN_EMERG "NULL\n");
        }
    }
    if(NULL != all_header_list){
        kfree(all_header_list);
    }
}

/**
 * 进行 header_list 的内存的释放
 * @param header_list
 */
void free_header_list(struct HeaderList* header_list){
    // 进行 validation_field_list 的释放
    struct ValidationField* entry, *tmp;
    list_for_each_entry_safe(entry, tmp, header_list->validation_field_list, list){
        if(entry != NULL){
            list_del(&entry->list);
            kfree(entry);
        } else {
            printk(KERN_EMERG "NULL\n");
        };
    }
    // 进行链表头的释放
    kfree(header_list->validation_field_list);
    // 进行header_list的释放
    kfree(header_list);
}