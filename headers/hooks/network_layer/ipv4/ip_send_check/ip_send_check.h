//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
#define LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
#include <net/ip.h>
#include "structure/header/lir_header.h"
#include "structure/header/icing_header.h"
#include "structure/header/epic_header.h"
#include "structure/header/opt_header.h"
#include "structure/header/selir_header.h"
#include "structure/header/fast_selir_header.h"
#include "structure/header/session_header.h"
#include "structure/header/multicast_session_header.h"
#include "structure/header/epic_session_header.h"
#include "structure/header/atlas_header.h"
#include "structure/header/multipath_selir_header.h"
#include "structure/header/multicast_selir_header.h"
#include "structure/header/multicast_opt_header.h"
#include "structure/header/sec_path_mab_header.h"
#include "structure/header/sec_path_mab_ack_header.h"
void lir_send_check(struct LiRHeader *pvh);
void icing_send_check(struct ICINGHeader* icing_header);
void epic_send_check(struct EpicHeader* epic_header);
void opt_send_check(struct OptHeader* opt_header);
void sec_path_mab_send_check(struct SecPathMabHeader* sec_path_mab_header);
void sec_path_mab_ack_send_check(struct SecPathMabAckHeader* sec_path_mab_ack_header);
void selir_send_check(struct SELiRHeader* selir_header);
void multicast_selir_send_check(struct MulticastSelirHeader* multicast_selir_header);
void multicast_opt_send_check(struct MulticastOptHeader* multicast_opt_header);
void fast_selir_send_check(struct FastSELiRHeader* fast_selir_header);
void session_setup_send_check(struct SessionHeader* session_header);
void multicast_session_setup_send_check(struct MulticastSessionHeader* session_header);
void epic_session_setup_send_check(struct EpicSessionHeader* epic_session_header);
void atlas_send_check(struct AtlasHeader* atlas_header);
void multipath_selir_send_check(struct MultipathSELiRHeader* multipath_selir_header);
#endif //LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
