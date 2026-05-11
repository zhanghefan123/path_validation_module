#include "structure/path_validation_structure.h"
#include "structure/interface/interface_table.h"
#include "structure/routing/variables.h"
#include "structure/routing/array_based_routing_table.h"
#include "structure/routing/hash_based_routing_table.h"
#include "structure/crypto/crypto_structure.h"

// 实际的变量定义
DEFINE_PER_CPU(struct pv_struct, validation_api);



struct pv_struct create_pv_struct(bool required_hash, bool required_hmac, bool required_bloom_filter,
                                  struct BloomFilter *template_bloom_filter) {
    struct pv_struct result = {};
    if (required_hash) {
        result.hash_api = generate_hash_api();
    } else {
        result.hash_api = NULL;
    }
    if (required_hmac) {
        result.hmac_api = generate_hmac_api();
    } else {
        result.hmac_api = NULL;
    }
    if (required_bloom_filter && (template_bloom_filter != NULL)) {
        result.bloom_filter = init_bloom_filter(template_bloom_filter->bf_effective_bits,
                                                template_bloom_filter->hash_seed,
                                                template_bloom_filter->number_of_hash_functions);
    } else {
        result.bloom_filter = NULL;
    }
    return result;
}

void free_pv_struct(struct pv_struct *pv_struct) {
    if (NULL != pv_struct->hash_api) {
        free_crypto_api(pv_struct->hash_api);
        pv_struct->hash_api = NULL;
    }
    if (NULL != pv_struct->hmac_api) {
        free_crypto_api(pv_struct->hmac_api);
        pv_struct->hmac_api = NULL;
    }
    if (NULL != pv_struct->bloom_filter) {
        delete_bloom_filter(pv_struct->bloom_filter);
        pv_struct->bloom_filter = NULL;
    }
    if (NULL != pv_struct->hbpct) {
        free_hbpct(pv_struct->hbpct);
        pv_struct->hbpct = NULL;
    }
}

/**
 * 初始化网络命名空间之中的 path_validation_structure
 * @param current_ns
 */
struct PathValidationStructure *init_pvs(void) {
    struct PathValidationStructure *pvs = (struct PathValidationStructure *) kmalloc(
            sizeof(struct PathValidationStructure), GFP_KERNEL);
    pvs->abrt = NULL;

    pvs->hbale = init_hbale(100); // 这里固定的bucket数量为100
    pvs->hbace = init_hbace(100); // 这里固定的 bucket 数量为 100
    pvs->llbmpt = init_llbpmt(); // 这里是一个链表

    pvs->hbrt = NULL;
    pvs->abit = NULL;
    pvs->bloom_filter = NULL;
    pvs->hbst = init_hbst(100); // 这里固定的 bucket 数量为 100
    pvs->hbest = init_hbest(100); // 这里固定的 bucket 数量为 100
    pvs->hash_api = generate_hash_api();
    pvs->hmac_api = generate_hmac_api();
    pvs->selir_info = init_selir_info();
    pvs->abpt = NULL;  // 等到之后进行初始化, 肯定不会超过 100 个节点
    pvs->sec_path_mab_settings = init_sec_path_mab_settings();


    return pvs;
}

/**
 * 进行 path_validation_structure 空间的释放
 * @param path_validation_structure 路径验证数据结构
 */
void free_pvs(struct PathValidationStructure *pvs) {
    if (NULL != pvs) {
        // 进行基于数组路由表的释放
        free_abrt(pvs->abrt);

        // 进行基于数组的预期 ack 表的释放
        free_hbale(pvs->hbale);
        // 进行基于链表的预期 ack 表的释放
        free_hbace(pvs->hbace);
        // 进行基于链表的预计要执行的变更表的释放
        free_llbpmt(pvs->llbmpt);

        // 进行基于哈希的路由表的释放
        free_hbrt(pvs->hbrt);
        // 进行基于数组的接口表的释放
        free_abit(pvs->abit);
        // 进行基于哈希的会话表的释放
        free_hbst(pvs->hbst);
        // 进行基于数组的多路径表的释放
        free_abpt(pvs->abpt);
        // 进行基于哈希的EPIC会话表的释放
        free_hbest(pvs->hbest);
        // 进行布隆过滤器的释放
        delete_bloom_filter(pvs->bloom_filter);
        // 进行 selir 信息的释放
        free_selir_info(pvs->selir_info);
// ---------------- 一旦进行这两个数据结构的释放就会出错 ----------------
        // 进行哈希数据结构的释放
        free_crypto_api(pvs->hash_api);
        // 进行 hmac 数据结构的释放
        free_crypto_api(pvs->hmac_api);
// ---------------- 一旦进行这两个数据结构的释放就会出错 ----------------
        if (NULL != pvs->sec_path_mab_settings) {
            free_sec_path_mab_settings(pvs->sec_path_mab_settings);
        }
        kfree(pvs);
    }
}


void
initialize_routing_table(struct PathValidationStructure *pvs, int routing_table_type, int number_of_routes_or_buckets) {
    if (ARRAY_BASED_ROUTING_TABLE_TYPE == routing_table_type) {
        pvs->abrt = init_abrt(number_of_routes_or_buckets);
        pvs->routing_table_type = ARRAY_BASED_ROUTING_TABLE_TYPE;
    } else if (HASH_BASED_ROUTING_TABLE_TYPE == routing_table_type) {
        pvs->hbrt = init_hbrt(number_of_routes_or_buckets);
        pvs->routing_table_type = HASH_BASED_ROUTING_TABLE_TYPE;
    } else {
        printk(KERN_EMERG "unsupported routing table type\n");
    }
}

void initialize_forwarding_table(struct PathValidationStructure *pvs, int number_of_interfaces) {
    // init forwarding table
    pvs->abit = init_abit(number_of_interfaces);
}

/**
 * 初始化多路径表
 * @param pvs
 * @param number_of_destinations
 */
void initialize_multipath_table(struct PathValidationStructure *pvs, int multipath_routing_type, int number_of_buckets,
                                int number_of_destinations, int number_of_relationships, int number_of_paths) {
    // 设置路由表类型
    pvs->routing_table_type = MULTIPATH_ROUTING_TABLE_TYPE;
    // 初始化路由表
    pvs->abpt = init_abpt(number_of_destinations, number_of_buckets, multipath_routing_type,
                          number_of_relationships, number_of_paths);
}

