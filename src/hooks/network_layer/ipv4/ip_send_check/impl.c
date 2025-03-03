#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

void lir_send_check(struct LiRHeader *pvh){
    pvh->check = 0;
    pvh->check = ip_fast_csum((unsigned char *)pvh, pvh->hdr_len / 4);
}

void icing_send_check(struct ICINGHeader* icing_header) {
    icing_header->check = 0;
    icing_header->check = ip_fast_csum((unsigned char*)icing_header, icing_header->hdr_len / 4);
}

void opt_send_check(struct OptHeader* opt_header){
    opt_header->check = 0;
    opt_header->check = ip_fast_csum((unsigned char*)opt_header, opt_header->hdr_len / 4);
}

void selir_send_check(struct SELiRHeader* selir_header){
    selir_header->check = 0;
    selir_header->check = ip_fast_csum((unsigned char*)selir_header, selir_header->hdr_len / 4);
}

void fast_selir_send_check(struct FastSELiRHeader* fast_selir_header){
    fast_selir_header->check = 0;
    fast_selir_header->check = ip_fast_csum((unsigned char*)fast_selir_header, fast_selir_header->hdr_len / 4);
}

void session_setup_send_check(struct SessionHeader* session_header){
    session_header->check = 0;
    session_header->check = ip_fast_csum((unsigned char*)session_header, session_header->hdr_len / 4);
}

void multicast_session_setup_send_check(struct MulticastSessionHeader* session_header){
    session_header->check = 0;
    session_header->check = ip_fast_csum((unsigned char*)session_header, session_header->hdr_len / 4);
}