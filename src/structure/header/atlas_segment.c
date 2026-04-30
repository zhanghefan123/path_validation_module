#include "structure/header/atlas_segment.h"
#include "tools/tools.h"

void free_atlas_segment(struct AtlasSegment* atlas_segment) {
    if (NULL != atlas_segment) {
        if (NULL != atlas_segment->array) {
                kfree(atlas_segment->array);
        }
        kfree(atlas_segment);
    }
}