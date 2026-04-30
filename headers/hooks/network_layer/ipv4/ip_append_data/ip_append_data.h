//
// Created by 张贺凡 on 2024/11/27.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_APPEND_DATA_H
#define LOADABLE_KERNEL_MODULE_IP_APPEND_DATA_H

#include <net/ip.h>
#include "structure/routing/routing_calc_res.h"
#include "structure/routing/multipath_res.h"

bool resolve_ip_append_data_inner_functions_address(void);


int self_defined__xx_append_data(struct sock *sk,
                                 struct flowi4 *fl4,
                                 struct sk_buff_head *queue,
                                 struct inet_cork *cork,
                                 struct page_frag *pfrag,
                                 int getfrag(void *from, char *to, int offset,
                                             int len, int odd, struct sk_buff *skb),
                                 void *from, int app_and_transport_len, int transport_hdr_len,
                                 unsigned int flags,
                                 struct InterfaceTableEntry* ite,
                                         int header_size);


#endif //LOADABLE_KERNEL_MODULE_IP_APPEND_DATA_H
