#include <linux/random.h>
#include "structure/routing/sec_path_mab_route.h"

void free_sec_path_mab_route(struct SecPathMabRoute* route){
    if(NULL != route){
        if(NULL != route->link_identifiers){
            kfree(route->link_identifiers);
        }
        if(NULL != route->sample_node_ids){
            kfree(route->sample_node_ids);
        }
        // 如果每次发送包的时候都进行 setsockopt 的指定性能会下降, 所以还是让内核空间生成采样序列
        if(NULL != route->sample_sequence){
            free_sequence(route->sample_sequence);
        }
        kfree(route);
    }
}


void free_sequence(struct SampleSequence* sample_sequence){
    if(NULL != sample_sequence){
        if (NULL != sample_sequence->actual_sequence){
            kfree(sample_sequence->actual_sequence);
        }
        kfree(sample_sequence);
    }
}

struct SampleSequence* generate_sequence(int number_of_sample_nodes, int sequence_length, int* sample_counts){
    struct SampleSequence *seq;
    int total_len = sequence_length;
    int idx = 0;
    int i, j;
    unsigned char tmp;

    if (!sample_counts || number_of_sample_nodes <= 0) return NULL;

    if (total_len <= 0) {
        return NULL;
    }


    // 分配结构体
    seq = kmalloc(sizeof(*seq), GFP_KERNEL);
    if (!seq) return NULL;
    seq->actual_sequence = kmalloc_array(total_len, sizeof(unsigned char), GFP_KERNEL);
    if (!seq->actual_sequence) { kfree(seq); return NULL; }

    seq->current_index = 0;
    seq->sequence_length = total_len;

    // 填充序列（节点编号 1,2,3...）
    for (i = 0; i < number_of_sample_nodes; i++) {
        int cnt = sample_counts[i];
        while (cnt-- > 0 && idx < total_len) {
            seq->actual_sequence[idx++] = i;
        }
    }

    // Fisher–Yates 内核安全随机洗牌
    for (i = total_len - 1; i > 0; i--) {
        j = get_random_u32() % (i + 1);
        tmp = seq->actual_sequence[i];
        seq->actual_sequence[i] = seq->actual_sequence[j];
        seq->actual_sequence[j] = tmp;
    }

    return seq;


//    struct SampleSequence* sample_sequence = (struct SampleSequence*)(kmalloc(sizeof(struct SampleSequence), GFP_KERNEL));
//    sample_sequence->current_index = 0;
//    sample_sequence->sequence_length = sequence_length;
//    sample_sequence->actual_sequence = (unsigned char*)kmalloc(sizeof(char) * sequence_length, GFP_KERNEL);
//    // 确保每个节点收到的都相等
//    int index;
//    for(index = 0; index < sequence_length; index++){
//        sample_sequence->actual_sequence[index] = (int)(index % number_of_sample_nodes);
//    }
//    // 进行随即洗牌
//    for (index = sequence_length - 1; index > 0; index--) {
//        u32 j;
//        int tmp;
//
//        // 获取 [0, i] 范围内的加密安全随机数
//        // get_random_u32_below() 在 Linux 6.0+ 引入，能消除取模偏差且是安全的。
//        // 如果你的内核版本较老，可以替换为：j = get_random_u32() % (i + 1);
//        j = get_random_u32() % (index + 1);
//
//        // 交换 sequence[i] 和 sequence[j]
//        tmp = sample_sequence->actual_sequence[index];
//        sample_sequence->actual_sequence[index] = sample_sequence->actual_sequence[j];
//        sample_sequence->actual_sequence[j] = tmp;
//    }
//
//    // 进行 sequence 的生成
//    return sample_sequence;
}

/**
 * 进行 sec_path_mab_route 之中 sequence 的重置
 * @param route sec_path_mab_route
 */
void reset_sec_path_mab_route_sequence(struct SecPathMabRoute* route, int sequence_length, int* counts){
    if(NULL != route) {
        if(NULL != route->sample_sequence){
            free_sequence(route->sample_sequence);
        }
        route->sample_sequence = generate_sequence(route->number_of_sample_nodes, sequence_length, counts);
    } else {
        printk(KERN_EMERG "reset_sec_path_mab_route_sequence: route is NULL\n");
    }
}

void test_generate_sample_sequence(void){
    const int node_count = 3;
    const int total_length = 100;
    int sample_counts[3] = {25, 35, 40};
    struct SampleSequence *seq;
    int count_check[3] = {0}; // 1/2/3
    int i;

    seq = generate_sequence(node_count, total_length, sample_counts);
    if (!seq) return;

    // 统计
    for (i = 0; i < seq->sequence_length; i++) {
        unsigned char n = seq->actual_sequence[i];
        if (n <= 2) {
            count_check[n]++;
        } else {
            pr_info("generate illegal index");
        }
    }

    pr_info("==== 数量验证 ====\n");
    pr_info("节点1 预期:%d 实际:%d\n", sample_counts[0], count_check[0]);
    pr_info("节点2 预期:%d 实际:%d\n", sample_counts[1], count_check[1]);
    pr_info("节点3 预期:%d 实际:%d\n", sample_counts[2], count_check[2]);

    kfree(seq->actual_sequence);
    kfree(seq);
}