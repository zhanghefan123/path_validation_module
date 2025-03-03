//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
#define LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
#include <net/ip.h>
#include "structure/header/lir_header.h"
#include "structure/header/icing_header.h"
#include "structure/header/opt_header.h"
#include "structure/header/selir_header.h"
#include "structure/header/fast_selir_header.h"
#include "structure/header/session_header.h"
#include "structure/header/multicast_session_header.h"
void lir_send_check(struct LiRHeader *pvh);
void icing_send_check(struct ICINGHeader* icing_header);
void opt_send_check(struct OptHeader* opt_header);
void selir_send_check(struct SELiRHeader* selir_header);
void fast_selir_send_check(struct FastSELiRHeader* fast_selir_header);
void session_setup_send_check(struct SessionHeader* session_header);
void multicast_session_setup_send_check(struct MulticastSessionHeader* session_header);
#endif //LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
