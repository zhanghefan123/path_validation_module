#include "structure/header/sec_path_mab_ack_header.h"

int get_sec_path_mab_ack_header_size(int length_of_path){
    int basic_header_size = sizeof(struct SecPathMabAckHeader);
    int path_part_size = sizeof(struct SecPathMabHopIdentifier) * (length_of_path);
    int validation_part_size = sizeof(struct SecPathMabAckValidationPart);
    return basic_header_size + path_part_size + validation_part_size;
}