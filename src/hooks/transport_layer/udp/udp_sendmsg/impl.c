#include <net/udp.h>
#include <net/udplite.h>
#include <linux/bpf-cgroup.h>
#include <linux/inetdevice.h>
#include <linux/bitops.h>
#include "api/test.h"
#include "tools/tools.h"
#include "structure/routing/variables.h"
#include "structure/namespace/namespace.h"
#include "structure/path_validation_sock_structure.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/transport_layer/udp/udp_sendmsg/udp_sendmsg.h"
#include "hooks/transport_layer/udp/udp_send_skb/udp_send_skb.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "api/option_resolver.h"


char *ip_cmsg_send_str = "ip_cmsg_send";

asmlinkage int (*orig_ip_cmsg_send)(struct sock *sk, struct msghdr *msg, struct ipcm_cookie *ipc, bool allow_ipv6);


/**
 * 解析 udp_sendmsg 内部的函数
 * @return
 */
bool resolve_udp_sendmsg_inner_functions(void) {
    LOG_WITH_EDGE("start to resolve udp_sendmsg inner functions address");
    // 解析结果
    bool resolve_result;
    // 所有的待初始化的函数的函数指针过程的数组
    void *functions[1];
    char *function_names[1] = {
            ip_cmsg_send_str,
    };
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    orig_ip_cmsg_send = functions[0];
    LOG_WITH_EDGE("end to resolve udp_sendmsg inner functions address");
    return resolve_result;
}

/**
 * 自定义的 udp_sendmsg
 * @param sk
 * @param msg
 * @param len
 * @return
 */
int self_defined_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) {
    // 起始时间
    u64 start_time = ktime_get_real_ns();
    u64 encryption_time_elapsed = 0;
    u64 enc_start_time;
    u64 enc_time_elapsed;
    struct inet_sock *inet = inet_sk(sk);
    struct udp_sock *up = udp_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
    struct flowi4 fl4_stack;
    struct flowi4 *fl4;
    int ulen = len;
    struct ipcm_cookie ipc;
    //    struct rtable *rt = NULL;  original code
    int free = 0;
    int connected = 0;
    __be32 daddr, faddr, saddr;
    __be16 dport;
    u8 tos;
    int err, is_udplite = IS_UDPLITE(sk);
    int corkreq = READ_ONCE(up->corkflag) || msg->msg_flags & MSG_MORE;
    int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
    struct sk_buff *skb;
    struct ip_options_data opt_copy;
    // zhf add variables
    // -----------------------------------------------------
    // 1. 路由计算结果
    struct RoutingCalcRes *rcr;
    // 2. 网络命名空间
    struct net *current_ns;
    // 3. 路径验证数据结构
    struct PathValidationStructure *pvs;
    // 4. 选项
    struct ip_options_rcu *option;
    // 5. 由选项解析的目的地
    struct UserSpaceInfo *dest_and_proto_info;
    // 6. 源节点
    int source;
    // 7. 变量赋值
    current_ns = sock_net(sk);
    pvs = get_pvs_from_ns(current_ns);
    option = inet->inet_opt;
    dest_and_proto_info = resolve_opt_for_dest_and_proto_info(option);
    if (NULL == dest_and_proto_info) {
        kfree_skb(skb);
        return 0;
    }
    source = pvs->node_id;
    // 8. 是否已经发送了会话建立的数据包
    bool sent_first_packet;
    // -----------------------------------------------------

    // zhf add new code -- search route
    // -----------------------------------------------------
    rcr = construct_rcr_with_user_space_info(pvs, dest_and_proto_info, source);
    if (NULL == rcr) {
        return -EINVAL;
    }
    // -----------------------------------------------------

    // 当长度超大, 返回消息大小错误信息
    if (len > 0xFFFF)
        return -EMSGSIZE;

    /*
     *	Check the flags.
     */

    // 不支持 MSG_OOB
    if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
        return -EOPNOTSUPP;

    // getfrag 负责从用户空间 mv 数据下来
    getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

    fl4 = &inet->cork.fl.u.ip4;


    ulen += sizeof(struct udphdr); // ulen 应该是用户数据大小, ulen + udp 首部 = 应用层 + 传输层大小

    // 验证地址
    // -----------------------------------------------------
    // usin 是一个 sockaddr_in --> 代表的是目的地址
    // usin->sin_addr --> 代表的是目的 ip
    // usin->sin_port --> 代表的是目的 port
    if (usin) {
        // 首先判断地址是否长度没错
        if (msg->msg_namelen < sizeof(*usin))
            return -EINVAL;
        // 接着判断协议簇是否没错
        if (usin->sin_family != AF_INET) {
            if (usin->sin_family != AF_UNSPEC)
                return -EAFNOSUPPORT;
        }
        // 初始化目的地址和目的端口
        // ---------------------------
        daddr = usin->sin_addr.s_addr;
        dport = usin->sin_port;
        // ---------------------------

        // 如果目的端口为0, 则返回错误
        if (dport == 0)
            return -EINVAL;
    }
    // -----------------------------------------------------

    // ipcm_init_sk 函数会使用 inet 套接字相关的信息来填充 ipc 结构体。这些信息用于 IP 层数据包的处理，比如源 IP 地址、目的 IP 地址、TTL、优先级等。
    // -----------------------------------------------------
    ipcm_init_sk(&ipc, inet);
    ipc.gso_size = READ_ONCE(up->gso_size);
    // -----------------------------------------------------

    // 这段代码主要处理的是通过 BPF（Berkeley Packet Filter）程序对 UDP 数据包进行过滤和处理
    // -----------------------------------------------------
    // 1. cgroup_bpf_enabled(CGROUP_UDP4_SENDMSG)：检查是否启用了 cgroup BPF 程序,
    // 用于过滤和处理 UDP 数据包的发送操作。CGROUP_UDP4_SENDMSG 是一个用于标识 UDPv4 发送消息的 cgroup 类型。
    // !connected：确保当前的套接字不是处于已连接状态。这个条件的目的是确保只对非连接套接字进行 BPF 程序处理。
    if (cgroup_bpf_enabled(CGROUP_UDP4_SENDMSG) && !connected) {
        // 2. 这一行调用了 BPF 程序，运行一个与 UDP 发送消息相关的 BPF 程序 BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK。
        // BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK 是用于调用 BPF 程序并对 UDP 发送数据包进行处理。
        err = BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, (struct sockaddr *) usin, &ipc.addr);
        if (err)
            // 如果上面的 BPF 程序执行返回了错误（err 不为零），则直接跳转到 out_free 标签，进行错误处理，可能是释放资源等操作。
            goto out_free;

        // 3. 由于 bpf 程序可能修改地址, 这里重新进行地址验证
        if (usin) {
            if (usin->sin_port == 0) {
                /* BPF program set invalid port. Reject it. */
                err = -EINVAL;
                goto out_free;
            }
            daddr = usin->sin_addr.s_addr;
            dport = usin->sin_port;
        }
    }
    // -----------------------------------------------------

    // saddr 指的是源地址, 在我们发送数据的时候他还没有被初始化, 依然为 0.0.0.0
    saddr = ipc.addr;
    // faddr 代表的是 final destination address
    // 在一些协议中，faddr 可能表示经过某些操作或选项（比如源路由）处理后的最终目标地址. 如果没有复杂的处理，faddr 和 daddr 是相同的。
    ipc.addr = faddr = daddr;
    // printk(KERN_EMERG "ipc.addr = faddr = daddr = %pI4", &ipc.addr); // ipc.addr = faddr = daddr = 192.168.0.10

    // 如果选项为源路由的话
    // -----------------------------------------------------
    if (ipc.opt && ipc.opt->opt.srr) {
        if (!daddr) {
            err = -EINVAL;
            goto out_free;
        }
        faddr = ipc.opt->opt.faddr; // 从源路由选项之中获取最终地址
        connected = 0;
    }
    // -----------------------------------------------------

    // 根据网络协议栈中的选项（如路由、QoS等）来设置Type of Service (ToS) 字段和路由选项
    // -----------------------------------------------------
    tos = get_rttos(&ipc, inet);
    if (sock_flag(sk, SOCK_LOCALROUTE) ||
        (msg->msg_flags & MSG_DONTROUTE) ||
        (ipc.opt && ipc.opt->opt.is_strictroute)) {
        tos |= RTO_ONLINK;
        connected = 0;
    }
    // -----------------------------------------------------


    // -----------------------------------------------------
    if (ipv4_is_multicast(daddr)) { // 判断是否为多播地址 224.0.0.0 到 239.255.255.255
        // ipc.oif 是指发送数据包时使用的输出接口的ifindex
        // 这里判断 ipc.oif 是否为空，或者检查 oif 是否为 L3（网络层）主设备接口。
        if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
            ipc.oif = inet->mc_index;
        if (!saddr)
            saddr = inet->mc_addr;
        connected = 0;
    } else if (!ipc.oif) {
        ipc.oif = inet->uc_index; // 如果未设置 oif，则使用 inet->uc_index 作为默认的单播接口索引。
    } else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
        // 这里检查目标地址是否为 IPv4 本地广播地址（即 255.255.255.255）。本地广播地址表示数据包应发送到本地网络上的所有设备。
        /* oif is set, packet is to local broadcast and
         * uc_index is set. oif is most likely set
         * by sk_bound_dev_if. If uc_index != oif check if the
         * oif is an L3 master and uc_index is an L3 slave.
         * If so, we want to allow the send using the uc_index.
         *
         * 如果 oif 已经设置，并且目标地址是本地广播地址，且 uc_index 被设置，那么就需要检查 oif 和 uc_index 是否匹配。
         * 如果 uc_index 不等于 oif，则检查 oif 是否为 L3 主设备，并且 uc_index 是否为 L3 从设备。这样做是为了确保能够通过单播接口进行发送。
         */
        if (ipc.oif != inet->uc_index &&
            ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
                                                      inet->uc_index)) {
            ipc.oif = inet->uc_index;
        }
    }

    // 如果是处于连接的状态 -> 直接从缓存之中拿路由 original code (uncalled)
    /*
    if (connected)
        rt = (struct rtable *) sk_dst_check(sk, 0); // 调用 sk_get_dest 拿到 struct dst_entry
    */

    // 基本都会进入到这里进行路由的计算 (called)
    // ----------------------------------------------------------------------------
    struct net *net = sock_net(sk);
    __u8 flow_flags = inet_sk_flowi_flags(sk);

    fl4 = &fl4_stack;

    flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos,
                       RT_SCOPE_UNIVERSE, sk->sk_protocol,
                       flow_flags,
                       faddr, saddr, dport, inet->inet_sport,
                       sk->sk_uid);

    security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
    // ----------------------------------------------------------------------------

    // 路由计算完成后，知道源地址是什么了, 就进行源地址的更新
    // ----------------------------------------------------------------------------
    saddr = rcr->ite->interface->ip_ptr->ifa_list->ifa_address;
    fl4->saddr = saddr;
    // ----------------------------------------------------------------------------

    if (!ipc.addr)
        daddr = ipc.addr = fl4->daddr;

    /* Lockless fast path for the non-corking case. */
    // 如果没有进行 cork (called)
    // ----------------------------------------------------------------------------
    if (!corkreq) {
        // 实验所需, 暂不打印
        // LOG_WITH_PREFIX("path validation send packet");
        int index;
        struct inet_cork cork;
        // 进行不同类型的路径验证协议的解析
        // ------------------------------------------------------------------------------
        if (LIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
            skb = self_defined_lir_make_skb(sk, fl4, getfrag, msg, ulen,
                                            sizeof(struct udphdr), &ipc,
                                            &cork, msg->msg_flags, rcr);
        } else if (ICING_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
            skb = self_defined_icing_make_skb(sk, fl4, getfrag, msg, ulen,
                                              sizeof(struct udphdr), &ipc,
                                              &cork, msg->msg_flags, rcr, &encryption_time_elapsed);
        } else {
            if (NULL == sk->path_validation_sock_structure) {
                sent_first_packet = false;
            } else {
                sent_first_packet = true;
            }
            if (sent_first_packet) { // 如果已经进行了会话的建立
                if (OPT_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
                    skb = self_defined_opt_make_skb(sk, fl4, getfrag, msg, ulen,
                                                    sizeof(struct udphdr), &ipc,
                                                    &cork, msg->msg_flags, rcr, &encryption_time_elapsed);
                } else if (SELIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
//                    unsigned char* memory = (unsigned char*)(kmalloc(sizeof(unsigned char) * 4, GFP_KERNEL));
//                    u64 start_hweight32 = ktime_get_real_ns();
//                    for(index = 0; index < 8; index++){
//                        int result = hweight32(*((u32*)memory));
//                    }
//                    printk(KERN_EMERG "time elapsed: %llu\n", ktime_get_real_ns() - start_time);
                    skb = self_defined_selir_make_skb(sk, fl4, getfrag, msg, ulen,
                                                      sizeof(struct udphdr), &ipc,
                                                      &cork, msg->msg_flags, rcr, &encryption_time_elapsed);
//                    kfree(memory);
                } else if (FAST_SELIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
                    skb = self_defined_fast_selir_make_skb(sk, fl4, getfrag, msg, ulen,
                                                           sizeof(struct udphdr), &ipc,
                                                           &cork, msg->msg_flags, rcr, &encryption_time_elapsed);
                } else if(MULTICAST_SELIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol){
                    skb = self_defined_multicast_selir_make_skb(sk, fl4, getfrag, msg, ulen,
                                                                sizeof(struct udphdr), &ipc,
                                                                &cork, msg->msg_flags, rcr);
                } else {
                    LOG_WITH_PREFIX("unsupported protocol");
                    return -EINVAL;
                }
            } else { // 如果尚且还没有进行会话的建立
                // 根据 rcr 之中的目的节点的数量进行判断
                if (rcr->number_of_routes == 1) {
                    skb = self_defined_session_make_skb(sk, fl4, getfrag, msg, ulen,
                                                        sizeof(struct udphdr), &ipc,
                                                        &cork, msg->msg_flags, rcr);
                } else {
                    skb = self_defined_multicast_session_make_skb(sk, fl4, getfrag, msg, ulen,
                                                                  sizeof(struct udphdr), &ipc,
                                                                  &cork, msg->msg_flags, rcr);
                }
            }
        }
        // ------------------------------------------------------------------------------
        // 添加 udp 首部进行发送
        // ------------------------------------------------------------------------------
        err = PTR_ERR(skb);
        if (!IS_ERR_OR_NULL(skb)) {
            // 当 skb_copy 的时候并不会进行 skb->sk 的拷贝
            // 这里可能是真正的阻塞的原因
            err = self_defined_udp_send_skb(skb, fl4,
                                            &cork, rcr,
                                            dest_and_proto_info->path_validation_protocol);
        }
        // ------------------------------------------------------------------------------
        goto out;
    }
    // ----------------------------------------------------------------------------



    out:
    // 进行处理时间的打印
    // ----------------------------------------------------------------------------
    u64 time_elapsed = ktime_get_real_ns() - start_time;
    if (sent_first_packet) {
        if (ICING_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
//            printk(KERN_EMERG "icing source sendmsg time elapsed: %llu ns\n", time_elapsed);
//            printk(KERN_EMERG "icing source encryption time elapsed: %llu ns\n", encryption_time_elapsed);
        } else if (OPT_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
//            printk(KERN_EMERG "opt source sendmsg time elapsed: %llu ns\n", time_elapsed);
//            printk(KERN_EMERG "opt source encryption time elapsed: %llu ns\n", encryption_time_elapsed);
        } else if (SELIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
//            printk(KERN_EMERG "selir source sendmsg time elapsed: %llu ns\n", time_elapsed);
//            printk(KERN_EMERG "selir source encryption time elapsed: %llu ns\n", encryption_time_elapsed);
        } else if (FAST_SELIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol) {
//            printk(KERN_EMERG "fast selir source sendmsg time elapsed: %llu ns\n", time_elapsed);
//            printk(KERN_EMERG "fast selir source encryption time elapsed: %llu ns\n", encryption_time_elapsed);
        } else if(MULTICAST_SELIR_VERSION_NUMBER == dest_and_proto_info->path_validation_protocol){
//            printk(KERN_EMERG "multicast selir source sendmsg time elapsed: %llu ns\n", time_elapsed);
        }
    }
    // ----------------------------------------------------------------------------


    out_free:
    if (free)
        kfree(ipc.opt);
    if (!err) {
        free_rcr(rcr);
        free_user_space_info(dest_and_proto_info);
        return (int) len;
    }

    /*
     * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
     * ENOBUFS might not be good (it's not tunable per se), but otherwise
     * we don't have a good statistic (IpOutDiscards but it can be too many
     * things).  We could add another new stat but at least for now that
     * seems like overkill.
     */
    if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
        UDP_INC_STATS(sock_net(sk),
                      UDP_MIB_SNDBUFERRORS, is_udplite);
    }
    return err;
}