#include "api/test.h"
#include "structure/crypto/bloom_filter.h"
#include "structure/crypto/crypto_structure.h"
#include "structure/rtt_estimator/rtt_estimator.h"
#include "structure/routing/sec_path_mab_route.h"
#include "tools/tools.h"

/**
 * 测试一些 api
 */
void test_apis(void){
    test_bloom_filter();
    test_crypto_apis();
    test_corrupt();
    test_generate_sample_sequence();
    test_rtt_estimator();
    test_uniform_sample_index();
}

/**
 * 判断 socket 是否是 lir socket
 * @param sk socket
 * @return
 */
int resolve_socket_type(struct sock* sk){
    if (sock_flag(sk, SOCK_DBG)){
        return LINK_IDENTIFIED_SOCKET_TYPE;
    } else {
        return NORMAL_SOCKET_TYPE;
    }
}