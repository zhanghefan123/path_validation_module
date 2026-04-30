//
// Created by zhf on 2026/4/14.
//

#ifndef PATH_VALIDATION_MODULE_RTT_ESTIMATOR_H
#define PATH_VALIDATION_MODULE_RTT_ESTIMATOR_H

#include <net/ip.h>

// 网络环境动态变化，有一个类似样本量，置信度类似的用来表征我们估计链路是否准确的值，基于这个值和网络环境来推batch大小，基于置信度和网络时延来推batch

struct RttEstimator {
    u32 srtt_us;     /* 平滑 RTT (注意：存储的是真实值的 8 倍) */
    u32 mdev_us;     /* RTT 偏差 (注意：存储的是真实值的 4 倍) */
    u32 rto_us;      /* 重传超时时间 */

    int updated_times; // 进行重新更新的次数
    u64 last_send_timestamp; // 最近发送的时间戳

    u32 min_rto_us;  /* 最小 RTO 限制 */
    u32 max_rto_us;  /* 最大 RTO 限制 */
};

void init_rtt_estimator(struct RttEstimator *est, u32 min_rto_us, u32 max_rto_us);

void update_rtt(struct RttEstimator *est, u32 sample_rtt_us);

void test_rtt_estimator(void);

#endif //PATH_VALIDATION_MODULE_RTT_ESTIMATOR_H
