#include "api/test.h"
#include "tools/tools.h"
#include "structure/header/tools.h"

__u16 get_source_from_skb(struct sk_buff* skb){
    int version = ip_hdr(skb)->version;
    if(LIR_VERSION_NUMBER == version){
        return lir_hdr(skb)->source;
    } else if(ICING_VERSION_NUMBER == version){
        return icing_hdr(skb)->source;
    } else if(OPT_DATA_VERSION_NUMBER == version){
        return opt_hdr(skb)->source;
    } else if(SELIR_VERSION_NUMBER == version){
        return selir_hdr(skb)->source;
    } else if(FAST_SELIR_VERSION_NUMBER == version){
        return fast_selir_hdr(skb)->source;
    } else if(MULTICAST_SELIR_VERSION_NUMBER == version){
        return selir_hdr(skb)->source;
    } else {
        LOG_WITH_PREFIX("unsupported version");
        return 0;
    }
}