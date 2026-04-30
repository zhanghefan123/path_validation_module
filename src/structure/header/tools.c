#include "api/test.h"
#include "tools/tools.h"
#include "structure/header/tools.h"
#include "structure/header/multicast_opt_header.h"


__u16 get_source_from_skb(struct sk_buff* skb){
    int version = ip_hdr(skb)->version;
    if(LIR_VERSION_NUMBER == version){
        return lir_hdr(skb)->source;
    } else if(ICING_VERSION_NUMBER == version){
        return icing_hdr(skb)->source;
    } else if(OPT_VERSION_NUMBER == version){
        return opt_hdr(skb)->source;
    } else if(SEC_PATH_MAB_VERSION_NUMBER == version){ // sec path mab version number 在这里执行
        return sec_path_mab_hdr(skb)->source;
    } else if(SELIR_VERSION_NUMBER == version){
        return selir_hdr(skb)->source;
    } else if(FAST_SELIR_VERSION_NUMBER == version){
        return fast_selir_hdr(skb)->source;
    } else if(MULTICAST_SELIR_VERSION_NUMBER == version){
        return multicast_selir_hdr(skb)->source;
    } else if(EPIC_VERSION_NUMBER == version){
        return epic_hdr(skb)->source;
    } else if(ATLAS_VERSION_NUMBER == version){
        return atlas_hdr(skb)->source;
    } else if(MULTIPATH_SELIR_VERSION_NUMBER == version){
        return multipath_selir_hdr(skb)->source;
    } else if(MULTICAST_OPT_VERSION_NUMBER == version){
        return multicast_opt_hdr(skb)->source;
    } else {
        LOG_WITH_PREFIX("unsupported version");
        return 0;
    }
}