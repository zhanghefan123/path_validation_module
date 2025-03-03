#include "structure/path_validation_sock_structure.h"

struct PathValidationSockStructure* init_pvss(void){
    struct PathValidationSockStructure* pvss = (struct PathValidationSockStructure*)(kmalloc(sizeof (struct PathValidationSockStructure), GFP_KERNEL));
    return pvss;
}


void free_pvss(struct PathValidationSockStructure* pvss){
    if(NULL != pvss){
        kfree(pvss);
    }
}
