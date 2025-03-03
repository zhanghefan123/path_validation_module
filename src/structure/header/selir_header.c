#include "tools/tools.h"
#include "structure/header/selir_header.h"

/**
 * 进行完整的报文头的打印
 * @param pvh 路径验证报文头
 */
void PRINT_SELIR_HEADER(struct SELiRHeader* seh){
    LOG_WITH_EDGE("selir header");
    printk(KERN_EMERG "version: %d\n", seh->version);
    printk(KERN_EMERG "ttl: %d\n", seh->ttl);
    printk(KERN_EMERG "protocol: %d\n", seh->protocol);
    printk(KERN_EMERG "frag_off: %d\n", ntohs(seh->frag_off));
    printk(KERN_EMERG "id: %d\n", seh->id);
    printk(KERN_EMERG "check: %d\n", seh->check);
    printk(KERN_EMERG "source: %d\n", seh->source);
    printk(KERN_EMERG "hdr_len: %d\n", seh->hdr_len);
    printk(KERN_EMERG "tot_len: %d\n", ntohs(seh->tot_len));
    printk(KERN_EMERG "ppf_len: %d\n", seh->ppf_len);
    printk(KERN_EMERG "dest_len: %d\n", seh->dest_len);
    LOG_WITH_EDGE("selir header");
}

unsigned char* calculate_selir_hash(struct shash_desc* hash_api, struct SELiRHeader* selir_header){
    // check 不作为静态字段来进行哈希
    int not_calculated_part = sizeof(__sum16);
    // 计算哈希并返回
    return calculate_hash(hash_api,
                          (unsigned char*)(selir_header),
                          sizeof(struct SELiRHeader) - not_calculated_part);
}