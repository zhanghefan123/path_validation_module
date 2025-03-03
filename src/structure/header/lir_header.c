#include "tools/tools.h"
#include "structure/header/lir_header.h"

/**
 * 进行完整的报文头的打印
 * @param pvh 路径验证报文头
 */
void PRINT_LIR_HEADER(struct LiRHeader* pvh){
    unsigned char* dest_pointer_start = (unsigned char*)(pvh) + sizeof(struct LiRHeader);
    unsigned char* bloom_pointer_start = (unsigned char*)(pvh) + sizeof(struct LiRHeader) + pvh->dest_len;
    unsigned char* application_pointer_start = (unsigned char*)(pvh) + sizeof(struct LiRHeader) + sizeof(struct udphdr);
    LOG_WITH_EDGE("lir header");
    // 1. 进行各个字段的打印
    printk(KERN_EMERG "version: %d\n", pvh->version);
    printk(KERN_EMERG "ttl: %d\n", pvh->ttl);
    printk(KERN_EMERG "protocol: %d\n", pvh->protocol);
    printk(KERN_EMERG "frag_off: %d\n", ntohs(pvh->frag_off));
    printk(KERN_EMERG "id: %d\n", pvh->id);
    printk(KERN_EMERG "check: %d\n", pvh->check);
    printk(KERN_EMERG "source: %d\n", pvh->source);
    printk(KERN_EMERG "hdr_len: %d\n", pvh->hdr_len);
    printk(KERN_EMERG "tot_len: %d\n", ntohs(pvh->tot_len));
    printk(KERN_EMERG "bf_len: %d\n", pvh->bf_len);
    printk(KERN_EMERG "dest_len: %d\n", pvh->dest_len);
    // 2. 进行目的的打印
    int index;
    for(index = 0; index < pvh->dest_len; index++){
        printk(KERN_EMERG "destination[%d]=%d\n",index+1, dest_pointer_start[index]);
    }
    // 3. 进行布隆过滤器的打印
    print_memory_in_hex(bloom_pointer_start, pvh->bf_len);
    LOG_WITH_EDGE("lir header");
    // 4. 进行应用层的打印
}