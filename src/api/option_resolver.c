#include "api/test.h"
#include "api/option_resolver.h"
#include "tools/tools.h"
/**
 * 解析选项, 得到目的地
 * type, length, number_of_destinations, destination1, destination2, ...
 * @param opt 选项
 * @return
 */
struct UserSpaceInfo* resolve_opt_for_dest_and_proto_info(struct ip_options_rcu* opt){
    int index;
    int path_validation_protocol = opt->opt.__data[PATH_VALIDATION_PROTOCOL_INDEX];
    if(LIR_VERSION_NUMBER == path_validation_protocol){
        // (type, length, path_validation_protocol, number_of_destinations, dest1, dest2, ..., alignment...)
        int number_of_destinations = opt->opt.__data[NUMBER_OF_DESTINATIONS_INDEX];
        struct UserSpaceInfo* destination_info = initialize_user_space_info(path_validation_protocol,
                                                                            number_of_destinations);
        for(index = 0; index < number_of_destinations; index++){
            destination_info->destinations[index] = opt->opt.__data[DESTINATIONS_START_INDEX + index];
        }
        return destination_info;
    } else if(ICING_VERSION_NUMBER == path_validation_protocol){
        // (type, length, path_validation_protocol, number_of_destinations, dest1, dest2, ..., alignment...)
        int number_of_destinations = opt->opt.__data[NUMBER_OF_DESTINATIONS_INDEX];
        struct UserSpaceInfo* destination_info = initialize_user_space_info(path_validation_protocol,
                                                                            number_of_destinations);
        for(index = 0; index < number_of_destinations; index++){
            destination_info->destinations[index] = opt->opt.__data[DESTINATIONS_START_INDEX + index];
        }
        return destination_info;
    } else if(OPT_VERSION_NUMBER == path_validation_protocol){
        // (type, length, path_validation_protocol, number_of_destinations, dest1, dest2, ..., alignment...)
        int number_of_destinations = opt->opt.__data[NUMBER_OF_DESTINATIONS_INDEX];
        struct UserSpaceInfo* destination_info = initialize_user_space_info(path_validation_protocol,
                                                                            number_of_destinations);
        for(index = 0; index < number_of_destinations; index++){
            destination_info->destinations[index] = opt->opt.__data[DESTINATIONS_START_INDEX + index];
        }
        return destination_info;
    } else if(SELIR_VERSION_NUMBER == path_validation_protocol || FAST_SELIR_VERSION_NUMBER == path_validation_protocol || MULTICAST_SELIR_VERSION_NUMBER == path_validation_protocol){
        // (type, length, path_validation_protocol, number_of_destinations, dest1, dest2, ..., alignment...)
        int number_of_destinations = opt->opt.__data[NUMBER_OF_DESTINATIONS_INDEX];
        struct UserSpaceInfo* destination_info = initialize_user_space_info(path_validation_protocol,
                                                                            number_of_destinations);
        for(index = 0; index < number_of_destinations; index++){
            destination_info->destinations[index] = opt->opt.__data[DESTINATIONS_START_INDEX + index];
        }
        return destination_info;
    } else {
        LOG_WITH_PREFIX("unsupported path validation protocol");
        return NULL;
    }
}