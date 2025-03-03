#include "tools/tools.h"
#include "structure/header/icing_header.h"

void PRINT_ICING_HEADER(struct ICINGHeader *icing_header) {
    LOG_WITH_EDGE("path validation header");
    // 1. 进行各个字段的打印
    printk(KERN_EMERG "version: %d\n", icing_header->version);
    printk(KERN_EMERG "ttl: %d\n", icing_header->ttl);
    printk(KERN_EMERG "protocol: %d\n", icing_header->protocol);
    printk(KERN_EMERG "frag_off: %d\n", ntohs(icing_header->frag_off));
    printk(KERN_EMERG "id: %d\n", icing_header->id);
    printk(KERN_EMERG "check: %d\n", icing_header->check);
    printk(KERN_EMERG "source: %d\n", icing_header->source);
    printk(KERN_EMERG "dest: %d\n", icing_header->dest);
    printk(KERN_EMERG "hdr_len: %d\n", icing_header->hdr_len);
    printk(KERN_EMERG "tot_len: %d\n", ntohs(icing_header->tot_len));
    printk(KERN_EMERG "length_of_path: %d\n", icing_header->length_of_path);
    printk(KERN_EMERG "current_path_index: %d\n", icing_header->current_path_index);
    // 2. 进行path的打印
    unsigned char *path_start_pointer = (unsigned char *) (icing_header) + sizeof(struct ICINGHeader);
    struct ICINGHop *path = (struct ICINGHop *) (path_start_pointer);
    int index;
    for (index = 0; index < icing_header->length_of_path; index++) {
        printk(KERN_EMERG "node_id: %d, link_identifier: %d\n", path[index].node_id, path[index].link_id);
    }
    // 3. 进行 expire 的打印
    int path_memory = icing_header->length_of_path * sizeof(struct ICINGHop);
    int expire_memory = icing_header->length_of_path * sizeof(struct Expire);
    unsigned char *expire_start_pointer = (unsigned char *) (icing_header) + sizeof(struct ICINGHeader) + path_memory;
    print_memory_in_hex(expire_start_pointer, expire_memory);
    // 3. 进行 verifier 的打印

    LOG_WITH_EDGE("path validation header");
}


unsigned char *calculate_icing_hash(struct shash_desc *hash_api, struct ICINGHeader *icing_header) {
    // check 和 current_path_index 不作为静态字段来进行哈希
    int not_calculated_part = sizeof(__sum16) + sizeof(__u16);
    // 计算哈希并返回
    return calculate_hash(hash_api,
                          (unsigned char *) (icing_header),
                          sizeof(struct ICINGHeader) - not_calculated_part);

}