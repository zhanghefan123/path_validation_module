# this is a make file for a kernel object
# see online for more information
CONFIG_MODULE_SIG=n
CONFIG_DEBUG_KMEMLEAK=y
# will build "hello.ko"
obj-m += pvm.o

# we have no file "hello.c" in this example
# therefore we specify: module hello.ko relies on
# main.c and greet.c ... it's this makefile module magic thing..
# see online resources for more information
# YOU DON'T need this IF you have *.c-file with the name of the
# final kernel module :)
pvm-objs := \
	src/api/ftrace_hook_api.o \
	src/api/hook_functions_api.o \
	src/api/check_srv6.o \
	src/api/test.o \
	src/api/netlink_router.o \
	src/api/netlink_handler.o \
	src/api/option_resolver.o \
	src/structure/path_validation_sock_structure.o \
	src/structure/path_validation_structure.o \
	src/structure/header/tools.o \
	src/structure/header/lir_header.o \
	src/structure/header/icing_header.o \
	src/structure/header/epic_header.o \
	src/structure/header/opt_header.o \
	src/structure/header/multicast_opt_header.o \
	src/structure/header/selir_header.o \
	src/structure/header/fast_selir_header.o \
	src/structure/header/atlas_header.o \
	src/structure/header/atlas_header_list.o \
	src/structure/header/atlas_segment.o \
	src/structure/header/atlas_validation_field.o \
	src/structure/header/multipath_selir_header.o \
	src/structure/header/multicast_selir_header.o \
	src/structure/header/sec_path_mab_header.o \
	src/structure/header/sec_path_mab_ack_header.o \
	src/structure/header/sec_path_mab_common.o \
	src/structure/namespace/namespace.o \
    src/structure/malicious/malicious_params.o \
	src/structure/crypto/crypto_structure.o \
	src/structure/crypto/bloom_filter.o \
    src/structure/routing/sec_path_mab_route.o \
	src/structure/routing/user_space_info.o \
	src/structure/interface/interface_table.o \
	src/structure/session/session_table.o \
	src/structure/session/epic_session_table.o \
	src/structure/routing/array_based_routing_table.o \
	src/structure/routing/array_based_multipath_table.o \
	src/structure/routing/hash_based_ack_list_table.o \
	src/structure/routing/hash_based_ack_cache_table.o \
	src/structure/routing/hash_based_routing_table.o \
	src/structure/routing/hash_based_pvf_cache_table.o \
    src/structure/routing/linked_list_based_malicious_params_table.o \
	src/structure/routing/routing_calc_res.o \
	src/structure/routing/multipath_res.o \
	src/structure/routing/routing_table_entry.o \
	src/structure/rtt_estimator/rtt_estimator.o \
	src/hooks/inet_sendmsg/impl.o \
	src/hooks/inet_sendmsg/hook.o \
	src/hooks/network_layer/ipv4/ip_flush_pending_frames/impl.o\
	src/hooks/network_layer/ipv6/ipv6_rcv/hook.o \
	src/hooks/network_layer/ipv6/ipv6_rcv/impl.o \
	src/hooks/network_layer/ipv6/ipv6_rcv_finish/impl.o \
	src/hooks/network_layer/ipv6/ip6_rcv_finish_core/impl.o \
	src/hooks/network_layer/ipv4/ip_local_deliver/impl.o \
	src/hooks/network_layer/ipv4/ip_append_data/impl.o \
	src/hooks/network_layer/ipv4/ip_local_out/impl.o \
	src/hooks/network_layer/ipv4/ip_make_skb/multipath_selir_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/atlas_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/lir_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/icing_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/epic_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/opt_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/multicast_opt_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/selir_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/fast_selir_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/session_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/epic_session_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/multicast_session_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/multicast_selir_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/sec_path_mab_make_skb.o \
	src/hooks/network_layer/ipv4/ip_make_skb/sec_path_mab_ack_make_skb.o \
	src/hooks/network_layer/ipv4/ip_output/impl.o \
	src/hooks/network_layer/ipv4/ip_rcv/selir_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/session_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/epic_session_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/epic_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/multipath_selir_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/atlas_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/multicast_session_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/fast_selir_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/ip_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/lir_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/icing_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/opt_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/multicast_opt_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/multicast_selir_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/sec_path_mab_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/sec_path_mab_ack_rcv.o \
	src/hooks/network_layer/ipv4/ip_rcv/hook.o \
	src/hooks/network_layer/ipv4/ip_send_check/impl.o \
	src/hooks/network_layer/ipv4/ip_send_skb/impl.o \
	src/hooks/network_layer/ipv4/ip_setup_cork/impl.o \
	src/hooks/network_layer/ipv4/ip_packet_forward/impl.o \
	src/hooks/transport_layer/tcp/tcp_v4_rcv/impl.o \
	src/hooks/transport_layer/tcp/tcp_v4_rcv/hook.o \
	src/hooks/transport_layer/tcp/tcp_rcv_established/impl.o \
	src/hooks/transport_layer/tcp/tcp_v4_do_rcv/impl.o \
	src/hooks/transport_layer/udp/udp_rcv/impl.o \
	src/hooks/transport_layer/udp/udp_send_skb/impl.o \
	src/hooks/transport_layer/udp/udp_sendmsg/impl.o \
	src/hooks/transport_layer/udp/udp_sendmsg/hook.o \
	src/prepare/resolve_function_address.o \
	src/tools/tools.o \
	src/module_starter.o \



OUTPUT_DIR = "./build"

# 北航服务器的 ccflags-y
ccflags-y += -I/home/zhf/Projects/emulator/path_validation_module/headers

# 树莓派的 ccflags-y
#ccflags-y += -I/home/zhf/Projects/emulator/raspberrypi_module/headers


all: compile
	echo "successful make"

compile:
	make -C /lib/modules/5.19.0/build/ M=$(PWD) modules # 北航服务器的 make 的过程
	# make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -C /lib/modules/5.19.17-LiP-Kernel/build/   M=$(PWD) modules # 树莓派的 make 的过程

mv:
	mv .*.cmd *.ko *.o *.mod *.mod.c Module.symvers modules.order $(OUTPUT_DIR)

clean:
	rm -rf .*.cmd *.ko *.o *.mod *.mod.c Module.symvers modules.order
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
