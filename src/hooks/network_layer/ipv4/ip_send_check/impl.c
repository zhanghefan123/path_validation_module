#include "structure/header/sec_path_mab_header.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"


void lir_send_check(struct LiRHeader *pvh){
    pvh->check = 0;
    pvh->check = ip_fast_csum((unsigned char *)pvh, pvh->hdr_len / 4);
}

void icing_send_check(struct ICINGHeader* icing_header) {
    icing_header->check = 0;
    icing_header->check = ip_fast_csum((unsigned char*)icing_header, icing_header->hdr_len / 4);
}

void epic_send_check(struct EpicHeader* epic_header){
    epic_header->check = 0;
    epic_header->check = ip_fast_csum((unsigned char*) epic_header, epic_header->hdr_len / 4);
}

void opt_send_check(struct OptHeader* opt_header){
    opt_header->check = 0;
    opt_header->check = ip_fast_csum((unsigned char*)opt_header, opt_header->hdr_len / 4);
}

void sec_path_mab_send_check(struct SecPathMabHeader* sec_path_mab_header){
    sec_path_mab_header->check = 0;
    sec_path_mab_header->check = ip_fast_csum((unsigned char*)sec_path_mab_header, sec_path_mab_header->hdr_len/4);
}

void sec_path_mab_ack_send_check(struct SecPathMabAckHeader* sec_path_mab_ack_header){
    sec_path_mab_ack_header->check = 0;
    sec_path_mab_ack_header->check = ip_fast_csum((unsigned char*)sec_path_mab_ack_header, sec_path_mab_ack_header->hdr_len/4);
}

void selir_send_check(struct SELiRHeader* selir_header){
    selir_header->check = 0;
    selir_header->check = ip_fast_csum((unsigned char*)selir_header, selir_header->hdr_len / 4);
}

void multicast_selir_send_check(struct MulticastSelirHeader* multicast_selir_header){
    multicast_selir_header->check = 0;
    multicast_selir_header->check = ip_fast_csum((unsigned char*)multicast_selir_header, multicast_selir_header->hdr_len / 4);
}

void multicast_opt_send_check(struct MulticastOptHeader* multicast_opt_header){
    multicast_opt_header->check = 0;
    multicast_opt_header->check = ip_fast_csum((unsigned char*)multicast_opt_header, multicast_opt_header->hdr_len / 4);
}

void fast_selir_send_check(struct FastSELiRHeader* fast_selir_header){
    fast_selir_header->check = 0;
    fast_selir_header->check = ip_fast_csum((unsigned char*)fast_selir_header, fast_selir_header->hdr_len / 4);
}

void session_setup_send_check(struct SessionHeader* session_header){
    session_header->check = 0;
    session_header->check = ip_fast_csum((unsigned char*)session_header, session_header->hdr_len / 4);
}

void epic_session_setup_send_check(struct EpicSessionHeader* epic_session_header){
    epic_session_header->check = 0;
    epic_session_header->check = ip_fast_csum((unsigned char*)epic_session_header, epic_session_header->hdr_len / 4);
}

void atlas_send_check(struct AtlasHeader* atlas_header){
    atlas_header->check = 0;
    atlas_header->check = ip_fast_csum((unsigned char*)atlas_header, atlas_header->hdr_len / 4);
}

void multipath_selir_send_check(struct MultipathSELiRHeader* multipath_selir_header){
    multipath_selir_header->check = 0;
    multipath_selir_header->check = ip_fast_csum((unsigned char* )multipath_selir_header, multipath_selir_header->hdr_len / 4);
}

void multicast_session_setup_send_check(struct MulticastSessionHeader* session_header){
    session_header->check = 0;
    session_header->check = ip_fast_csum((unsigned char*)session_header, session_header->hdr_len / 4);
}