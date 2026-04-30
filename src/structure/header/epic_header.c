#include "tools/tools.h"
#include "structure/header/epic_header.h"
#include "structure/header/epic_fields_length.h"

void PRINT_EPIC_HEADER(struct EpicHeader* epic_header){
    LOG_WITH_EDGE("path validation header");

    // 1. 进行基础头的所有字段的打印
    printk(KERN_EMERG "version: %d\n", epic_header->version);
    printk(KERN_EMERG "ttl: %d\n", epic_header->ttl);
    printk(KERN_EMERG "protocol: %d\n", epic_header->protocol);
    printk(KERN_EMERG "frag_off: %d\n", ntohs(epic_header->frag_off));
    printk(KERN_EMERG "id: %d\n", epic_header->id);
    printk(KERN_EMERG "check: %d\n", epic_header->check);
    printk(KERN_EMERG "source: %d\n", epic_header->source);
    printk(KERN_EMERG "dest: %d\n", epic_header->dest);
    printk(KERN_EMERG "hdr_len: %d\n", epic_header->hdr_len);
    printk(KERN_EMERG "tot_len: %d\n", ntohs(epic_header->tot_len));
    printk(KERN_EMERG "length_of_path: %d\n", epic_header->length_of_path);
    printk(KERN_EMERG "current_path_index: %d\n", epic_header->current_path_index);

    // 2. 进行 path 的打印
    struct EpicPathPart* epic_path_part = get_epic_path_part_start_pointer(epic_header);
    int index;
    for(index = 0; index < epic_header->length_of_path; index++){
        printk(KERN_EMERG "node_id: %d, link_identifier: %d\n",
               epic_path_part->hop_identifiers[index].node_id,
               epic_path_part->hop_identifiers[index].link_id);
    }

    LOG_WITH_EDGE("path validation header");
}

void PRINT_EPIC_HOP_IDENTIFIER(struct EpicHopIdentifier* epic_hop_identifier){
    char output[50];
    snprintf(output, sizeof(output), "HI[linkid: %d, incoming linkid: %d, nodeid: %d]\n",
             epic_hop_identifier->link_id, epic_hop_identifier->incoming_link_id, epic_hop_identifier->node_id);
    printk(KERN_EMERG "%s", output);
}


//  * SAT1 --LID1--> SAT2 --LID2--> SAT3 --LID3--> SAT4 三跳的路径
//   length_of_path = 3
//   path[0] node_id = SAT2 link_identifier = L2 current_path_index=0
//   path[1] node_id = SAT3 link_identifier = L3 current_path_index=1
//   path[2] node_id = SAT4 current_path_index = 2
int get_epic_header_size(int length_of_path){
    int basic_header_size = sizeof(struct EpicHeader);
    int path_part_size =  get_epic_header_path_part_size(length_of_path);
    int validation_part_size = get_epic_header_validation_part_size(length_of_path);
//    return basic_header_size + path_part_size + validation_part_size;
    return basic_header_size + path_part_size + validation_part_size;
}

// 8 + 16 + 8 + 16
int get_epic_header_path_part_size(int length_of_path){
    return PATH_TIMESTAMP_LENGTH + (int) ADDRESS_LENGTH * 2 + (int) (length_of_path * sizeof(struct EpicHopIdentifier)); // HIi
}

// Tspkt + VSD + S1,V1 ... Si,Vi
int get_epic_header_validation_part_size(int length_of_path){
//    printk(KERN_EMERG "Validation hop size: %d\n", sizeof (struct ValidationPerHop));
    return PACKET_TIMESTAMP_LENGTH + DESTINATION_VALIDATION_LENGTH + (int) (length_of_path * sizeof(struct ValidationPerHop));
}

unsigned char* calculate_epic_hash(struct shash_desc* hash_api, struct EpicHeader* epic_header){
    int not_calculated_part = sizeof(__sum16) + sizeof(__u16);
    return calculate_hash(hash_api,
                          (unsigned char*)(epic_header),
                          sizeof(struct EpicHeader) - not_calculated_part);
}