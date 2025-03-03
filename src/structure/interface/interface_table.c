#include "structure/interface/interface_table.h"

/**
 * 进行接口表的初始化
 * @param number_of_interfaces
 * @return
 */
struct ArrayBasedInterfaceTable* init_abit(int number_of_interfaces){
    // 分配内存
    struct ArrayBasedInterfaceTable *ibrt = (struct ArrayBasedInterfaceTable*)kmalloc(sizeof(struct ArrayBasedInterfaceTable), GFP_KERNEL);
    // 设置接口数量
    ibrt->number_of_interfaces = number_of_interfaces;
    // 为接口表分配内存
    ibrt->interfaces = (struct InterfaceTableEntry**)kmalloc(sizeof(struct InterfaceTableEntry*) * number_of_interfaces, GFP_KERNEL);
    // 进行创建结果返回
    return ibrt;
}

/**
 * 进行接口表的释放
 * @param abit
 */
void free_abit(struct ArrayBasedInterfaceTable* abit){
    if(NULL != abit){
        if(NULL != abit->interfaces){
            int index;
            for(index = 0; index < abit->number_of_interfaces; index++){
                if(NULL != abit->interfaces[index]){
                    free_ite(abit->interfaces[index]);
                }
            }
            kfree(abit->interfaces);
            abit->interfaces = NULL;
        }
        kfree(abit);
        abit = NULL;
    }
}

/**
 * 利用链路标识进行接口表的查找
 * @param pvs 路径验证数据结构
 * @param link_identifier 链路标识
 * @return
 */
struct InterfaceTableEntry* find_ite_in_abit(struct ArrayBasedInterfaceTable* abit, int link_identifier){
    int index;
    struct InterfaceTableEntry* result = NULL;
    for(index = 0; index < abit->number_of_interfaces; index++){
        if(abit->interfaces[index]->link_identifier == link_identifier){
            result = abit->interfaces[index];
            break;
        }
    }
    return result;
}

/**
 * 进行接口表项的初始化
 * @param effective_bytes 总的 bf 有效字节数
 * @return
 */
struct InterfaceTableEntry* init_ite(int index, int effective_bytes){
    // 为 interface_table_entry 分配内存
    struct InterfaceTableEntry* ite = (struct InterfaceTableEntry*)(kmalloc(sizeof(struct InterfaceTableEntry), GFP_KERNEL));
    // 设置索引
    ite->index = index;
    // 为 bitset 分配内存
    ite->bitset = (unsigned char*)(kmalloc(effective_bytes, GFP_KERNEL));
    // 返回结果
    return ite;
}


/**
 * 添加 interface table entry (ite) 到 abit
 * @param link_identifier 链路标识
 * @param interface 接口
 * @param index 索引
 * @param bf 的有效位数
 */
void add_ite_to_abit(struct ArrayBasedInterfaceTable* abit, struct InterfaceTableEntry* ite){
    abit->interfaces[ite->index] = ite;
}

/**
 * 进行接口表表项的释放
 */
void free_ite(struct InterfaceTableEntry* entry){
    if(NULL != entry){
        if(NULL != entry->bitset){
            kfree(entry->bitset);
            entry->bitset = NULL;
        }
        entry = NULL;
    }
}
