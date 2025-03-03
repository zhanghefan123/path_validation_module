#include "tools/tools.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "structure/header/lir_header.h"
#include "structure/namespace/namespace.h"

char *ip_local_error_str = "ip_local_error";
asmlinkage void (*orig_ip_local_error)(struct sock *sk, int err, __be32 daddr, __be16 dport, u32 info);

/**
 * 进行 ip_append_data 的解析
 * @return
 */
bool resolve_ip_append_data_inner_functions_address(void) {
    LOG_WITH_EDGE("start to resolve ip_append_data inner functions address");
    // 解析结果
    bool resolve_result;
    // 所有的待初始化的函数的函数指针过程的数组
    void *functions[1];
    char *function_names[1] = {
            ip_local_error_str,
    };
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    orig_ip_local_error = functions[0];
    LOG_WITH_EDGE("end to resolve ip_append_data inner functions address");
    return resolve_result;
}

// 原本在 udp_sendmsg 之中进行过调用, 后续被删除了
/*
int self_defined_ip_append_data(struct sock *sk, struct flowi4 *fl4,
                                int getfrag(void *from, char *to, int offset, int len,
                                            int odd, struct sk_buff *skb),
                                void *from, int length, int transhdrlen,
                                struct ipcm_cookie *ipc, struct rtable **rtp,
                                unsigned int flags) {
    struct inet_sock *inet = inet_sk(sk);
    int err;

    if (flags & MSG_PROBE)
        return 0;

    if (skb_queue_empty(&sk->sk_write_queue)) {
        err = self_defined_ip_setup_cork(sk, &inet->cork.base, ipc, rtp);
        if (err)
            return err;
    } else {
        transhdrlen = 0;
    }

    return self_defined__ip_append_data(sk, fl4, &sk->sk_write_queue, &inet->cork.base,
                                        sk_page_frag(sk), getfrag,
                                        from, length, transhdrlen, flags);
}
*/

/**
 *
 * @param sk
 * @param fl4
 * @param queue
 * @param cork
 * @param pfrag
 * @param getfrag
 * @param from
 * @param app_and_transport_len
 * @param transport_hdr_len
 * @param flags
 * @param rcr
 * @param header_size zhf add parameter 代表头部的长度
 * @return
 */
int self_defined__xx_append_data(struct sock *sk,
                                 struct flowi4 *fl4,
                                 struct sk_buff_head *queue,
                                 struct inet_cork *cork,
                                 struct page_frag *pfrag,
                                 int getfrag(void *from, char *to, int offset,
                                             int len, int odd, struct sk_buff *skb),
                                 void *from, int app_and_transport_len, int transport_hdr_len,
                                 unsigned int flags,
                                 struct RoutingCalcRes* rcr,
                                 int header_size) {
    // zhf add code 获取 path validation structure
    // -----------------------------------
    struct net *current_ns = sock_net(sk);
    struct PathValidationStructure* pvs = get_pvs_from_ns(current_ns);
    // -----------------------------------
    struct inet_sock *inet = inet_sk(sk);
    struct ubuf_info *uarg = NULL;
    struct sk_buff *skb;
    int hh_len;
    int mtu;
    int copy;
    int err;
    int offset = 0;
    unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
    int csummode = CHECKSUM_NONE;
    unsigned int wmem_alloc_delta = 0;
    bool paged, extra_uref = false;
    u32 tskey = 0;

    skb = skb_peek_tail(queue); // 从队列尾部拿到 skb
    mtu = cork->gso_size ? IP_MAX_MTU : cork->fragsize;
    paged = !!cork->gso_size;

    if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
        sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
        tskey = atomic_inc_return(&sk->sk_tskey) - 1;

    hh_len = LL_RESERVED_SPACE(rcr->ite->interface);

    // zhf add code 进行路径长度的获取
    // -----------------------------------------------------------
    int length_of_header = header_size;
    // -----------------------------------------------------------

    fragheaderlen = length_of_header;
    // 因为 IP 首部的片段偏移量只有13位, 并以8字节为单位，否则首部的便宜量就无法进行正确的设置，这里是进行8字节对齐下的最大结果
    maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
    maxnonfragsize = ip_sk_ignore_df(sk) ? IP_MAX_MTU : mtu;

    // 检查当前累计的数据包大小 + 即将添加的应用层数据长度 (app_len) 是否超过了非分片数据包所允许的最大的长度 - 分片头的长度。
    if (cork->length + app_and_transport_len > maxnonfragsize - fragheaderlen) {
        orig_ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,mtu);
        return -EMSGSIZE;
    }

    /*
     * transhdrlen > 0 means that this is the first fragment and we wish
     * it won't be fragmented in the future.
     * 传输层头部大于0 代表这是第一个包
     */
    if (transport_hdr_len &&
        app_and_transport_len + fragheaderlen <= mtu &&
        rcr->ite->interface->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM) &&
        (!(flags & MSG_MORE) || cork->gso_size) &&
        ((rcr->ite->interface->features & NETIF_F_HW_ESP_TX_CSUM)))
        csummode = CHECKSUM_PARTIAL;

    // 这段代码是Linux内核网络栈中处理零拷贝（zero-copy）发送的一部分。
    // 它涉及到如何在不进行数据拷贝的情况下将用户空间的数据直接传递给网络协议栈，从而提高性能，尤其是在高带宽或大数据量传输的场景下。
    // ------------------------------------------------------------------------------------------------------------
    // 首先判断
    //   1. 用户是否在发送的时候调用了 MSG_ZEROCOPY (一般的情况下是不会进行调用的)
    //   2. 确保有实际的应用层数据需要发送
    //   3. 检查套接字 sk 是否启用了零拷贝特性。
    // 这一般不会满足。
    if (flags & MSG_ZEROCOPY && app_and_transport_len && sock_flag(sk, SOCK_ZEROCOPY)) {
        uarg = msg_zerocopy_realloc(sk, app_and_transport_len, skb_zcopy(skb));
        if (!uarg)
            return -ENOBUFS;
        extra_uref = !skb_zcopy(skb);    /* only ref on new uarg */
        if (rcr->ite->interface->features & NETIF_F_SG &&
            csummode == CHECKSUM_PARTIAL) {
            paged = true;
        } else {
            uarg->zerocopy = 0;
            skb_zcopy_set(skb, uarg, &extra_uref);
        }
    }
    // ------------------------------------------------------------------------------------------------------------

    cork->length += app_and_transport_len;

    /* So, what's going on in the loop below?
     *
     * We use calculated fragment length to generate chained skb,
     * each of segments is IP fragment ready for sending to network after
     * adding appropriate IP header.
     */


    // 如果 skb 为空, 那么就分配新的 skb
    if (!skb)
        goto alloc_new_skb;

    // 1. 当 app_len 即用户数据 > 0 的时候继续进行发送
    while (app_and_transport_len > 0) {
        /* Check if the remaining data fits into current packet. */
        // copy 表示剩余的 mtu 的空间
        copy = mtu - skb->len;
        // 如果剩余的空间 < 数据包的长度, 说明要使用一个新的分组
        if (copy < app_and_transport_len)
            copy = maxfraglen - skb->len;  // 那么尝试使用最大分片的长度
        // 如果 copy <=0 代表当前数据包已经满了，需要创建新的数据包或者分片
        if (copy <= 0) {
            char *data;
            unsigned int datalen;
            unsigned int fraglen;
            unsigned int fraggap;
            unsigned int alloclen, alloc_extra;
            unsigned int pagedlen;
            struct sk_buff *skb_prev;
            alloc_new_skb:
            skb_prev = skb;
            if (skb_prev)
                fraggap = skb_prev->len - maxfraglen;
            else
                fraggap = 0;

            /*
             * If remaining data exceeds the mtu,
             * we know we need more fragment(s).
             */
            datalen = app_and_transport_len + fraggap;
            if (datalen > mtu - fragheaderlen)
                datalen = maxfraglen - fragheaderlen;
            fraglen = datalen + fragheaderlen;
            pagedlen = 0;

            alloc_extra = hh_len + 15;
            alloc_extra += 0; // 原来是 + extension_header_length

            /* The last fragment gets additional space at tail.
             * Note, with MSG_MORE we overallocate on fragments,
             * because we have no idea what fragment will be
             * the last.
             */
            if (datalen == app_and_transport_len + fraggap)
                alloc_extra += 0; // rt.dst.trailer_len

            if ((flags & MSG_MORE) &&
                !(rcr->ite->interface->features & NETIF_F_SG))
                alloclen = mtu;
            else if (!paged &&
                     (fraglen + alloc_extra < SKB_MAX_ALLOC ||
                      !(rcr->ite->interface->features & NETIF_F_SG)))
                alloclen = fraglen;
            else {
                alloclen = min_t(int, fraglen, MAX_HEADER);
                pagedlen = fraglen - alloclen;
            }

            alloclen += alloc_extra;

            if (transport_hdr_len) {
                skb = sock_alloc_send_skb(sk, alloclen,
                                          (flags & MSG_DONTWAIT), &err);
            } else {
                skb = NULL;
                if (refcount_read(&sk->sk_wmem_alloc) + wmem_alloc_delta <=
                    2 * sk->sk_sndbuf)
                    skb = alloc_skb(alloclen,
                                    sk->sk_allocation);
                if (unlikely(!skb))
                    err = -ENOBUFS;
            }
            if (!skb)
                goto error;

            /*
             *	Fill in the control structures
             */
            skb->ip_summed = csummode;
            skb->csum = 0;
            skb_reserve(skb, hh_len);
            /*
             *	Find where to start putting bytes.
             */
            data = skb_put(skb, fraglen - pagedlen);
            skb_set_network_header(skb, 0);
            skb->transport_header = (skb->network_header +
                                     fragheaderlen);
            data += fragheaderlen + 0;

            if (fraggap) {
                skb->csum = skb_copy_and_csum_bits(
                        skb_prev, maxfraglen,
                        data + transport_hdr_len, fraggap);
                skb_prev->csum = csum_sub(skb_prev->csum,
                                          skb->csum);
                data += fraggap;
                pskb_trim_unique(skb_prev, maxfraglen);
            }

            copy = datalen - transport_hdr_len - fraggap - pagedlen;
            if (copy > 0 && getfrag(from, data + transport_hdr_len, offset, copy, fraggap, skb) < 0) {
                err = -EFAULT;
                kfree_skb(skb);
                goto error;
            }

            offset += copy;
            app_and_transport_len -= copy + transport_hdr_len;
            transport_hdr_len = 0;
            csummode = CHECKSUM_NONE;

            /* only the initial fragment is time stamped */
            skb_shinfo(skb)->tx_flags = cork->tx_flags;
            cork->tx_flags = 0;
            skb_shinfo(skb)->tskey = tskey;
            tskey = 0;
            skb_zcopy_set(skb, uarg, &extra_uref);

            if ((flags & MSG_CONFIRM) && !skb_prev)
                skb_set_dst_pending_confirm(skb, 1);

            /*
             * Put the packet on the pending queue.
             */
            if (!skb->destructor) {
                skb->destructor = sock_wfree;
                skb->sk = sk;
                wmem_alloc_delta += skb->truesize;
            }
            __skb_queue_tail(queue, skb);
            continue;
        }

        // 如果剩余部分 > app_len 的长度
        if (copy > app_and_transport_len)
            copy = app_and_transport_len;

        if (!(rcr->ite->interface->features & NETIF_F_SG) &&
            skb_tailroom(skb) >= copy) {
            unsigned int off;

            off = skb->len;
            if (getfrag(from, skb_put(skb, copy),
                        offset, copy, off, skb) < 0) {
                __skb_trim(skb, off);
                err = -EFAULT;
                goto error;
            }
        } else if (!uarg || !uarg->zerocopy) {
            int i = skb_shinfo(skb)->nr_frags;

            err = -ENOMEM;
            if (!sk_page_frag_refill(sk, pfrag))
                goto error;

            if (!skb_can_coalesce(skb, i, pfrag->page,
                                  pfrag->offset)) {
                err = -EMSGSIZE;
                if (i == MAX_SKB_FRAGS)
                    goto error;

                __skb_fill_page_desc(skb, i, pfrag->page,
                                     pfrag->offset, 0);
                skb_shinfo(skb)->nr_frags = ++i;
                get_page(pfrag->page);
            }
            copy = min_t(int, copy, pfrag->size - pfrag->offset);
            if (getfrag(from,
                        page_address(pfrag->page) + pfrag->offset,
                        offset, copy, skb->len, skb) < 0)
                goto error_efault;

            pfrag->offset += copy;
            skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
            skb->len += copy;
            skb->data_len += copy;
            skb->truesize += copy;
            wmem_alloc_delta += copy;
        } else {
            err = skb_zerocopy_iter_dgram(skb, from, copy);
            if (err < 0)
                goto error;
        }
        offset += copy;
        app_and_transport_len -= copy;
    }

    if (wmem_alloc_delta)
        refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
    return 0;

    error_efault:
    err = -EFAULT;
    error:
    net_zcopy_put_abort(uarg, extra_uref);
    cork->length -= app_and_transport_len;
    IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
    refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
    return err;
}