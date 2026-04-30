//
// Created by zhf on 2025/12/12.
//

#ifndef PATH_VALIDATION_MODULE_ATLAS_TAG_H
#define PATH_VALIDATION_MODULE_ATLAS_TAG_H
struct AtlasTag{
    unsigned char type;
    unsigned char index;
    unsigned char removed;
};

static inline bool is_tag_removed(struct AtlasTag* tag){
    return tag->removed == 1;
}

static inline void remove_tag(struct AtlasTag* tag) {
    tag->removed = 1;
}

#endif //PATH_VALIDATION_MODULE_ATLAS_TAG_H
