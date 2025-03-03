#include "structure/namespace/namespace.h"

/**
 * 将 path_validation_structure 设置到 net namespace 之中
 * @param path_validation_structure
 */
void set_pvs_in_ns(struct net *ns,struct PathValidationStructure *pvs) {
    if(NULL == ns->path_validation_structure){
        ns->path_validation_structure = (void*)pvs;
    }
}

/**
 * 从 net namespace 之中获取 path_validation_structure
 * @param ns 网络命名空间
 * @return
 */
struct PathValidationStructure* get_pvs_from_ns(struct net* ns){
    if(NULL != ns->path_validation_structure){
        return (struct PathValidationStructure*)(ns->path_validation_structure);
    } else {
        return NULL;
    }
}