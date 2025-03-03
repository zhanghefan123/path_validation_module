//
// Created by zhf on 2024/12/7.
//

#ifndef PATH_VALIDATION_MODULE_IP_FLUSH_PENDING_FRAMES_H
#define PATH_VALIDATION_MODULE_IP_FLUSH_PENDING_FRAMES_H
#include <net/ip.h>
void __ip_flush_pending_frames(struct sock *sk,
                               struct sk_buff_head *queue,
                               struct inet_cork *cork);
#endif //PATH_VALIDATION_MODULE_IP_FLUSH_PENDING_FRAMES_H
