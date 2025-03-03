#include "tools/tools.h"
#include "structure/header/opt_header.h"
#include "api/test.h"

unsigned char* calculate_opt_hash(struct shash_desc* hash_api, struct OptHeader* opt_header){
    // check 和 current_path_index 无需进行计算
    int not_calculated_part = sizeof(__sum16) + sizeof(__u16);
    return calculate_hash(hash_api,
                          (unsigned char*)(opt_header),
                          sizeof(struct OptHeader) - not_calculated_part);
}

void PRINT_OPT_HEADER(struct OptHeader* opt_header){
    LOG_WITH_EDGE("opt header");
    // 1. 进行各个字段的打印
    printk(KERN_EMERG "version: %d\n", opt_header->version);
    printk(KERN_EMERG "ttl: %d\n", opt_header->ttl);
    printk(KERN_EMERG "protocol: %d\n", opt_header->protocol);
    printk(KERN_EMERG "frag_off: %d\n", ntohs(opt_header->frag_off)); // frag_off 的正常输出情况是 16384
    printk(KERN_EMERG "id: %d\n", opt_header->id);
    printk(KERN_EMERG "source: %d\n", opt_header->source);
    printk(KERN_EMERG "dest: %d\n", opt_header->dest);
    printk(KERN_EMERG "hdr_len: %d\n", opt_header->hdr_len);
    printk(KERN_EMERG "tot_len: %d\n", ntohs(opt_header->tot_len));
    printk(KERN_EMERG "check: %d\n", opt_header->check);
    printk(KERN_EMERG "current_path_index: %d\n", opt_header->current_path_index);
    // 2. 判断版本类型
    if(OPT_DATA_VERSION_NUMBER == opt_header->version){
        LOG_WITH_PREFIX("current not support opt data"); // not option data
    } else {
        LOG_WITH_PREFIX("unsupported opt header");
    }
    LOG_WITH_EDGE("opt header");
}