#include <net/ip.h>
#include "api/test.h"
#include "structure/routing/multipath_res.h"
#include "structure/header/atlas_segment.h"

struct MultipathRes* init_mres(int destination, struct InterfaceTableEntry* ite, struct AtlasSegment* segment, struct OutputInterfaceToPathsMapping* selected_mapping, struct list_head* segments, int routing_type, int max_path_length){
    struct MultipathRes* multipathRes = (struct MultipathRes*)kmalloc(sizeof(struct MultipathRes), GFP_KERNEL);
    multipathRes->destination = destination;
    multipathRes->ite = ite;
    multipathRes->selected_segment = segment;
    multipathRes->selected_mapping = selected_mapping;
    multipathRes->segments = segments;
    multipathRes->max_path_length = max_path_length;
    // ---------------- [11111] --------------- 5位都为1, 代表5条路径都不裁剪
    // ---------------- 统计 segment 的数量 ----------------
    int number_of_segments = 0;
    if(ROUTING_TYPE_ATLAS == routing_type){
        struct AtlasSegment* atlas_segment;
        struct list_head* position;
        list_for_each(position, segments){
            atlas_segment = list_entry(position, struct AtlasSegment, list);
            if (NULL != atlas_segment){
                number_of_segments++;
            }
        }
    } else if(ROUTING_TYPE_MULTIPATH_SELIR == routing_type){
        struct RoutingTableEntry* rte;
        struct list_head* position;
        list_for_each(position, segments){
            rte = list_entry(position, struct RoutingTableEntry, list);
            if (NULL != rte){
                number_of_segments++;
            }
        }
    } else {
        printk(KERN_EMERG "unsupported routing type when init mres\n");
    }
    multipathRes->number_of_segments = number_of_segments;
    // ---------------- 统计 segment 的数量 ----------------
    return multipathRes;
}

struct MultipathRes* construct_mres(struct PathValidationStructure* pvs,  int destination, int path_validation_protocol){
    // 找到对应的 segment
    if(ATLAS_VERSION_NUMBER == path_validation_protocol){
        if(ROUTING_TYPE_ATLAS != pvs->abpt->routing_type){
            printk(KERN_EMERG "multipath routing table type = %d not ROUTING_TYPE_ATLAS\n", pvs->abpt->routing_type);
            return NULL;
        }
        // 找到 segments
        struct list_head* segments = find_segments_or_paths_in_abpt(pvs->abpt, destination);
        // 找到出接口
        struct AtlasSegment* selected_segment = find_output_interface_in_abpt_for_atlas(pvs->abpt, pvs->node_id, destination);
        // 为空则返回 NULL
        if (NULL == selected_segment){
            printk(KERN_EMERG "cannot find segment\n");
            return NULL;
        }
        struct MultipathRes* mres = init_mres(destination, selected_segment->ite,  selected_segment, NULL, segments, pvs->abpt->routing_type, pvs->abpt->max_path_length);
        return mres;
    } else if(MULTIPATH_SELIR_VERSION_NUMBER == path_validation_protocol){
        if(ROUTING_TYPE_MULTIPATH_SELIR != pvs->abpt->routing_type){
            printk(KERN_EMERG "multipath routing table type = %d not ROUTING_TYPE_MULTIPATH_SELIR\n", pvs->abpt->routing_type);
            return NULL;
        }
        // 找到 paths
        struct list_head* paths = find_segments_or_paths_in_abpt(pvs->abpt, destination);
        // 判断是否是 split node
        if (0 == pvs->abpt->number_of_interface_to_path_mappings){
            // 找到出接口
            struct InterfaceTableEntry* selected_ite = find_output_interface_in_abpt_for_multipath_selir(pvs->abpt, pvs->abit, destination);
            // 为空则返回 NULL
            if (NULL == selected_ite){
                return NULL;
            }
            struct MultipathRes* mres = init_mres(destination, selected_ite, NULL, NULL, paths, pvs->abpt->routing_type, pvs->abpt->max_path_length);
            return mres;
        } else {
            struct OutputInterfaceToPathsMapping* selected_mapping = find_output_interface_to_paths_mapping(pvs->abpt);
            if (NULL == selected_mapping){
                return NULL;
            }
            struct MultipathRes* mres = init_mres(destination, selected_mapping->ite, NULL, selected_mapping, paths, pvs->abpt->routing_type, pvs->abpt->max_path_length);
            return mres;
        }
    } else {
        printk(KERN_EMERG "construct mres with unsupported version number %d\n", path_validation_protocol);
        return NULL;
    }
}

/**
 * 要注意在哪里进行释放
 * @param mres
 */
void free_mres(struct MultipathRes* mres){
    if(NULL != mres){
        kfree(mres);
    }
}