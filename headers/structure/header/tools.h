//
// Created by 张贺凡 on 2024/12/9.
//

#ifndef PATH_VALIDATION_MODULE_TOOLS_H
#define PATH_VALIDATION_MODULE_TOOLS_H
#include <net/ip.h>
#include "structure/header/lir_header.h"
#include "structure/header/icing_header.h"
#include "structure/header/opt_header.h"
#include "structure/header/selir_header.h"
#include "structure/header/fast_selir_header.h"
__u16 get_source_from_skb(struct sk_buff* skb);
#endif //PATH_VALIDATION_MODULE_TOOLS_H
