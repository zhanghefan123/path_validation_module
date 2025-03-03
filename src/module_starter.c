//
// Created by kernel-dbg on 24-2-1.
//
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include "api/hook_functions_api.h"
#include "prepare/resolve_function_address.h"
#include "tools/tools.h"
#include "api/test.h"
#include "api/netlink_router.h"
#include "structure/namespace/namespace.h"
#include "structure/path_validation_structure.h"

/**
 * 进行网络命名空间的初始化
 * @param net 网络命名空间
 * @return
 */
static int __net_init module_net_init(struct net* current_ns){
    LOG_WITH_EDGE("net init process");
    // 1. 初始化 path_validation_structure
    struct PathValidationStructure* pvs = init_pvs();
    current_ns->path_validation_structure = NULL;
    // 2. 设置到 net namespace 之中
    set_pvs_in_ns(current_ns, pvs);
    LOG_WITH_EDGE("net init process");
    return 0;
}

/**
 * 进行网络命名空间的释放
 * @param net 网络命名空间
 * 无返回值
 */
static void __net_exit module_net_exit(struct net* current_ns){
    LOG_WITH_EDGE("net exit process");
    // 1. 取出 path_validation_structure
    struct PathValidationStructure* pvs = get_pvs_from_ns(current_ns);
    // 2. 释放 path_validation_structure
    free_pvs(pvs);
    LOG_WITH_EDGE("net exit process");
}

/**
 * 记住网络命名空间的相关操作
 */
static struct pernet_operations net_namespace_operations = {
        .init = module_net_init,
        .exit = module_net_exit
};

/**
 * 自己编写的模块的启动方法
 * 无参数
 * @return 正常返回 0 非正常返回非 0
 */
static int __init module_init_function(void){
    bool resolve_result;
    register_pernet_subsys(&net_namespace_operations);
    // 1. 进行内核函数地址的解析
    resolve_result = resolve_function_address();
    if (!resolve_result){
        return -1;
    }
    // 2. 进行测试
    test_apis();

    // 3. 进行 netlink server 的注册
    netlink_server_init();

    // 4. 开始进行 hook 的安装
    start_install_hooks();
    return 0;
}

/**
 * 自己编写的模块的结束方法
 * 无参数
 * 无返回值
 */
static void __exit module_exit_function(void){
    unregister_pernet_subsys(&net_namespace_operations);

    // 进行 netlink server 的卸载
    netlink_server_exit();

    // 进行 hook 的卸载
    exit_uninstall_hooks();
}

module_init(module_init_function);
module_exit(module_exit_function);

MODULE_LICENSE("GPL");