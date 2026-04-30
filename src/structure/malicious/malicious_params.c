#include <net/ip.h>
#include "structure/malicious/malicious_params.h"

struct MaliciousParams* init_malicious_params(void){
    struct MaliciousParams* malicious_params = (struct MaliciousParams*)(kmalloc(sizeof(struct MaliciousParams), GFP_KERNEL));
    memset(malicious_params, 0, sizeof(struct MaliciousParams));
    return malicious_params;
}

void free_malicious_params(struct MaliciousParams* malicious_params){
    if(NULL != malicious_params){
        kfree(malicious_params);
    }
}