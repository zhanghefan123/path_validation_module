#include "structure/header/atlas_validation_field.h"

struct ValidationField* create_validation_field_copy(struct ValidationField* original){
    struct ValidationField* validation_field = (struct ValidationField *) kmalloc(sizeof(struct ValidationField), GFP_KERNEL);
    INIT_LIST_HEAD(&(validation_field->list));
    validation_field->type = original->type;
    validation_field->segment = original->segment;
    validation_field->validation_node_index = original->validation_node_index;
    memcpy(validation_field->validation_field_desc, original->validation_field_desc, sizeof(original->validation_field_desc));
    memcpy(validation_field->validation_field, original->validation_field, sizeof(original->validation_field));
    return validation_field;
}