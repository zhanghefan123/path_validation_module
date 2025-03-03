cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project("Path Validation Module" VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(KernelHeaders REQUIRED)


# find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
# thanks to "merseyviking" from stack overflow
add_definitions(-D__KERNEL__ -DMODULE)

# this is needed in order for CLion IDE to provide syntax highlightning
# this is independent from the actual kernel object that is built
add_executable(lkm
        src/api/ftrace_hook_api.c
        src/api/hook_functions_api.c
        src/api/check_srv6.c
        src/api/test.c
        src/api/netlink_router.c
        src/api/netlink_handler.c
        src/api/option_resolver.c

        src/structure/path_validation_sock_structure.c
        src/structure/session/session_table.c
        src/structure/crypto/crypto_structure.c
        src/structure/crypto/bloom_filter.c
        src/structure/path_validation_structure.c
        src/structure/interface/interface_table.c
        src/structure/namespace/namespace.c
        src/structure/routing/user_space_info.c
        src/structure/routing/array_based_routing_table.c
        src/structure/routing/hash_based_routing_table.c
        src/structure/routing/routing_calc_res.c
        src/structure/routing/routing_table_entry.c
        src/structure/header/fast_selir_header.c
        src/structure/header/selir_header.c
        src/structure/header/lir_header.c
        src/structure/header/icing_header.c
        src/structure/header/opt_header.c
        src/structure/header/tools.c
        src/hooks/inet_sendmsg/impl.c
        src/hooks/inet_sendmsg/hook.c

        src/hooks/transport_layer/tcp/tcp_v4_rcv/hook.c
        src/hooks/transport_layer/tcp/tcp_v4_rcv/impl.c
        src/hooks/transport_layer/tcp/tcp_v4_do_rcv/impl.c
        src/hooks/transport_layer/tcp/tcp_rcv_established/impl.c
        src/hooks/transport_layer/udp/udp_rcv/impl.c
        src/hooks/transport_layer/udp/udp_send_skb/impl.c
        src/hooks/transport_layer/udp/udp_sendmsg/impl.c
        src/hooks/transport_layer/udp/udp_sendmsg/hook.c

        src/hooks/network_layer/ipv4/ip_flush_pending_frames/impl.c
        src/hooks/network_layer/ipv4/ip_local_deliver/impl.c
        src/hooks/network_layer/ipv4/ip_local_out/impl.c
        src/hooks/network_layer/ipv4/ip_send_check/impl.c
        src/hooks/network_layer/ipv4/ip_output/impl.c
        src/hooks/network_layer/ipv4/ip_rcv/fast_selir_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/selir_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/lir_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/icing_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/opt_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/session_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/multicast_session_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/multicast_selir_rcv.c
        src/hooks/network_layer/ipv4/ip_rcv/hook.c
        src/hooks/network_layer/ipv4/ip_append_data/impl.c
        src/hooks/network_layer/ipv4/ip_make_skb/lir_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/icing_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/opt_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/selir_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/selir_fast_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/session_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/multicast_session_make_skb.c
        src/hooks/network_layer/ipv4/ip_make_skb/multicast_selir_make_skb.c
        src/hooks/network_layer/ipv4/ip_send_skb/impl.c
        src/hooks/network_layer/ipv4/ip_setup_cork/impl.c
        src/hooks/network_layer/ipv4/ip_packet_forward/impl.c

        src/hooks/network_layer/ipv6/ipv6_rcv/hook.c
        src/hooks/network_layer/ipv6/ipv6_rcv/impl.c
        src/hooks/network_layer/ipv6/ipv6_rcv_finish/impl.c
        src/hooks/network_layer/ipv6/ip6_rcv_finish_core/impl.c

        src/prepare/resolve_function_address.c
        src/tools/tools.c
        src/module_starter.c

)

set(HEADERS_DIR
        /usr/src/linux-hwe-5.19-headers-5.19.0-41/include
        /usr/src/linux-hwe-5.19-headers-5.19.0-41/arch/x86/include
        headers)

# CLion IDE will find symbols from <linux/*>
target_include_directories("lkm" PRIVATE ${HEADERS_DIR})