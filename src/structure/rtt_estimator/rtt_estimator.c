#include "structure/rtt_estimator/rtt_estimator.h"


/*
 * 初始化估测器 (对应 Python 的 __init__)
 */
void init_rtt_estimator(struct RttEstimator *est, u32 min_rto_us, u32 max_rto_us) {
    est->srtt_us = 0;
    est->mdev_us = 0;
    est->rto_us = 1000000; // 初始 RTO 设为 1 秒, 1000 ms
    est->min_rto_us = min_rto_us;
    est->max_rto_us = max_rto_us;
}

/*
 * 核心更新逻辑 (对应 Python 的 update)
 * 参数 sample_rtt_us 是最新测得的往返时间 (微秒)
 */
void update_rtt(struct RttEstimator *est, u32 sample_rtt_us) {
    est->updated_times += 1;
    long m = sample_rtt_us; // 使用带符号的长整型，因为计算差值可能会出现负数

    if (est->srtt_us == 0) {
        /* 1. 第一次测量：初始化 */
        /* 真实 SRTT = sample_rtt，存储 8 倍，所以左移 3 位 */
        est->srtt_us = m << 3;

        /* 真实 RTTVAR = sample_rtt / 2。
         * 存储 4 倍，即 (m / 2) * 4 = m * 2，所以左移 1 位
         */
        est->mdev_us = m << 1;
    } else {
        /* 2. 后续测量：动态更新 */

        /* 计算差值：m = SampleRTT - 真实SRTT
         * 真实 SRTT 是 est->srtt_us 右移 3 位
         */
        m -= (est->srtt_us >> 3);

        /* 3. 更新 SRTT (等价于 Python 的 self.srtt = 7/8 * self.srtt + 1/8 * sample)
         * 这是一个非常巧妙的数学等价:
         * 放大 8 倍的 SRTT += 差值，就正好完成了 1/8 的平滑！
         */
        est->srtt_us += m;

        /* 4. 更新偏差 (等价于 Python 的 self.rttvar = 3/4 * rttvar + 1/4 * abs(差值)) */
        if (m < 0) {
            m = -m; // 取绝对值
        }

        /* 差值绝对值减去当前的真实 RTTVAR (mdev_us 右移 2 位) */
        m -= (est->mdev_us >> 2);

        /* 放大 4 倍的 RTTVAR += (差值绝对值 - 真实RTTVAR)
         * 正好完成了 1/4 的平滑！
         */
        est->mdev_us += m;
    }

    /* 5. 计算 RTO = 真实SRTT + 4 * 真实RTTVAR
     * 真实 SRTT = srtt_us >> 3
     * 真实 4 * RTTVAR 刚好就等于 mdev_us，直接加上即可，无需乘法！
     */
    est->rto_us = (est->srtt_us >> 3) + est->mdev_us;

    /* 6. 夹紧边界值 */
    if (est->rto_us < est->min_rto_us){
        est->rto_us = est->min_rto_us;
    }else if (est->rto_us > est->max_rto_us){
        est->rto_us = est->max_rto_us;
    }

}

void test_rtt_estimator(void){
    struct RttEstimator est;
    u32 simulated_rtts[] = {100000, 105000, 98000, 500000, 200000};
    int num_samples;
    int index;

    // 初始化 RTT 估算器
    init_rtt_estimator(&est, 50000, 600000);

    num_samples = ARRAY_SIZE(simulated_rtts); // 内核推荐，比 sizeof 安全

    printk(KERN_EMERG "packet id | test RTT(ms) | SRTT(ms) | RTTVAR(ms) | RTO(ms)\n");
    printk(KERN_EMERG "---------------------------------------------------------------\n");

    for (index = 0; index < num_samples; index++) {
        u32 rtt_us = simulated_rtts[index];
        u32 srtt_ms, rttvar_ms, rto_ms, test_ms;

        update_rtt(&est, rtt_us);

        // 内核【不能用浮点数】，全部用整数除法 + 放大显示
        test_ms = rtt_us / 1000;                // 测试 RTT ms
        srtt_ms = (est.srtt_us >> 3) / 1000;    // 平滑 RTT ms
        rttvar_ms = (est.mdev_us >> 2) / 1000;    // RTT 方差 ms
        rto_ms = est.rto_us / 1000;           // 超时时间 ms

        printk(KERN_EMERG "#%d\t | %-12u | %-10u | %-11u | %u\n",
               index + 1,
               test_ms,
               srtt_ms,
               rttvar_ms,
               rto_ms);
    }
}