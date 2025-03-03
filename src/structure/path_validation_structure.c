#include "structure/path_validation_structure.h"
#include "structure/interface/interface_table.h"
#include "structure/routing/variables.h"
#include "structure/routing/array_based_routing_table.h"
#include "structure/routing/hash_based_routing_table.h"
#include "structure/crypto/crypto_structure.h"
#include "tools/tools.h"


/**
 * 初始化网络命名空间之中的 path_validation_structure
 * @param current_ns
 */
struct PathValidationStructure *init_pvs(void) {
    struct PathValidationStructure *pvs = (struct PathValidationStructure *) kmalloc(
            sizeof(struct PathValidationStructure), GFP_KERNEL);
    pvs->abrt = NULL;
    pvs->hbrt = NULL;
    pvs->abit = NULL;
    pvs->bloom_filter = NULL;
    pvs->hbst = init_hbst(100); // 这里固定的 bucket 数量为 100
    pvs->hash_api = generate_hash_api();
    pvs->hmac_api = generate_hmac_api();
    pvs->selir_info = init_selir_info();
    return pvs;
}


/**
 * 进行 path_validation_structure 空间的释放
 * @param path_validation_structure 路径验证数据结构
 */
void free_pvs(struct PathValidationStructure *pvs) {
    if(NULL != pvs) {
//        // 进行基于数组路由表的释放
        free_abrt(pvs->abrt);
//        // 进行基于哈希的路由表的释放
        free_hbrt(pvs->hbrt);
//        // 进行基于数组的接口表的释放
        free_abit(pvs->abit);
//        // 进行基于哈希的会话表的释放
        free_hbst(pvs->hbst);
//        // 进行布隆过滤器的释放
        delete_bloom_filter(pvs->bloom_filter);
          // 进行 selir 信息的释放
        free_selir_info(pvs->selir_info);

// ---------------- 一旦进行这两个数据结构的释放就会出错 ----------------
        // 进行哈希数据结构的释放
        free_crypto_api(pvs->hash_api);
        // 进行 hmac 数据结构的释放
        free_crypto_api(pvs->hmac_api);
// ---------------- 一旦进行这两个数据结构的释放就会出错 ----------------
        kfree(pvs);
    }
}


/**
 * 初始化路径验证数据结构
 * @param number_of_routes 总的路由条数
 * @param number_of_interfaces 总的接口数量
 */
void initialize_routing_and_forwarding_table(struct PathValidationStructure *pvs,
                                             int routing_table_type,
                                             int number_of_routes_or_buckets,
                                             int number_of_interfaces) {
    if (ARRAY_BASED_ROUTING_TABLE_TYPE == routing_table_type) {
        pvs->abrt = init_abrt(number_of_routes_or_buckets);
        pvs->routing_table_type = ARRAY_BASED_ROUTING_TABLE_TYPE;
    } else {
        pvs->hbrt = init_hbrt(number_of_routes_or_buckets);
        pvs->routing_table_type = HASH_BASED_ROUTING_TABLE_TYPE;
    }
    pvs->abit = init_abit(number_of_interfaces);
}
