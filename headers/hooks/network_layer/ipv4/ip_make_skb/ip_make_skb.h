//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
#define LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H

#include <net/ip.h>
#include "structure/routing/routing_calc_res.h"
#include "structure/routing/multipath_res.h"

struct sk_buff *self_defined_lir_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          int getfrag(void *from, char *to, int offset,
                                                      int len, int odd, struct sk_buff *skb),
                                          void *from, int length, int transhdrlen,
                                          struct ipcm_cookie *ipc,
                                          struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr);

struct sk_buff *self_defined__lir_make_skb(struct sock *sk,
                                           struct flowi4 *fl4,
                                           struct sk_buff_head *queue,
                                           struct inet_cork *cork,
                                           struct RoutingCalcRes *rcr);

struct sk_buff *self_defined_icing_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            int getfrag(void *from, char *to, int offset,
                                                        int len, int odd, struct sk_buff *skb),
                                            void *from, int length, int transhdrlen,
                                            struct ipcm_cookie *ipc,
                                            struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr,
                                            u64 *make_skb_time_elapsed,
                                            u64 *enc_time_elapsed);

struct sk_buff *self_defined__icing_make_skb(struct sock *sk,
                                             struct flowi4 *fl4,
                                             struct sk_buff_head *queue,
                                             struct inet_cork *cork,
                                             struct RoutingCalcRes *rcr,
                                             u64 *enc_time_elapsed);

struct sk_buff *self_defined_epic_make_skb(struct sock *sk,
                                           struct flowi4 *fl4,
                                           int getfrag(void *from, char *to, int offset,
                                                       int len, int odd, struct sk_buff *skb),
                                           void *from, int length, int transhdrlen,
                                           struct ipcm_cookie *ipc,
                                           struct inet_cork *cork, unsigned int flags,
                                           struct EpicSessionTableEntry *este,
                                           u64 *make_skb_time_elapsed,
                                           u64 *enc_time_elapsed);

struct sk_buff *self_defined__epic_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            struct sk_buff_head *queue,
                                            struct inet_cork *cork,
                                            struct EpicSessionTableEntry *este,
                                            u64 *enc_time_elapsed,
                                            int app_udp_len);

struct sk_buff *self_defined_atlas_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            int getfrag(void *from, char *to, int offset,
                                                        int len, int odd, struct sk_buff *skb),
                                            void *from, int length, int transhdrlen,
                                            struct ipcm_cookie *ipc,
                                            struct inet_cork *cork, unsigned int flags,
                                            struct MultipathRes *mres,
                                            u64 *make_skb_time_elapsed,
                                            u64 *turn_time_elapsed,
                                            u64 *integrate_time_elapsed);

struct sk_buff *self_defined__atlas_make_skb(struct sock *sk,
                                             struct flowi4 *fl4,
                                             struct sk_buff_head *queue,
                                             struct inet_cork *cork,
                                             struct MultipathRes *mres,
                                             int app_and_transport_length,
                                             u64 *turn_time_elapsed,
                                             u64 *integrate_time_elapsed);


struct sk_buff *self_defined_opt_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          int getfrag(void *from, char *to, int offset,
                                                      int len, int odd, struct sk_buff *skb),
                                          void *from, int length, int transhdrlen,
                                          struct ipcm_cookie *ipc,
                                          struct inet_cork *cork, unsigned int flags,
                                          struct RoutingCalcRes *rcr,
                                          u64 *make_skb_time_elapsed,
                                          u64 *enc_time_elapsed);

struct sk_buff *self_defined__opt_make_skb(struct sock *sk,
                                           struct flowi4 *fl4,
                                           struct sk_buff_head *queue,
                                           struct inet_cork *cork,
                                           struct RoutingCalcRes *rcr,
                                           u64 *enc_time_elapsed);

struct sk_buff *self_defined_sec_path_make_skb(struct sock *sk,
                                               struct flowi4 *fl4,
                                               int getfrag(void *from, char *to, int offset,
                                                           int len, int odd, struct sk_buff *skb),
                                               void *from, int length, int transhdrlen,
                                               struct ipcm_cookie *ipc,
                                               struct inet_cork *cork, unsigned int flags,
                                               struct SecPathMabRoute *sec_path_mab_route);

struct sk_buff *self_defined__sec_path_make_skb(struct sock *sk,
                                                struct flowi4 *fl4,
                                                struct sk_buff_head *queue,
                                                struct inet_cork *cork,
                                                struct SecPathMabRoute *sec_path_mab_route,
                                                int app_and_transport_length);

struct sk_buff *self_defined_session_make_skb(struct sock *sk,
                                              struct flowi4 *fl4,
                                              int getfrag(void *from, char *to, int offset,
                                                          int len, int odd, struct sk_buff *skb),
                                              void *from, int length, int transhdrlen,
                                              struct ipcm_cookie *ipc,
                                              struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr);

struct sk_buff *self_defined__session_make_skb(struct sock *sk,
                                               struct flowi4 *fl4,
                                               struct sk_buff_head *queue,
                                               struct inet_cork *cork,
                                               struct RoutingCalcRes *rcr);


struct sk_buff *self_defined_epic_session_make_skb(struct sock *sk,
                                                   struct flowi4 *fl4,
                                                   int getfrag(void *from, char *to, int offset,
                                                               int len, int odd, struct sk_buff *skb),
                                                   void *from, int length, int transhdrlen,
                                                   struct ipcm_cookie *ipc,
                                                   struct inet_cork *cork, unsigned int flags,
                                                   struct RoutingCalcRes *rcr);

struct sk_buff *self_defined__epic_session_make_skb(struct sock *sk,
                                                    struct flowi4 *fl4,
                                                    struct sk_buff_head *queue,
                                                    struct inet_cork *cork,
                                                    struct RoutingCalcRes *rcr);


struct sk_buff *self_defined_multicast_session_make_skb(struct sock *sk,
                                                        struct flowi4 *fl4,
                                                        int getfrag(void *from, char *to, int offset,
                                                                    int len, int odd, struct sk_buff *skb),
                                                        void *from, int length, int transhdrlen,
                                                        struct ipcm_cookie *ipc,
                                                        struct inet_cork *cork, unsigned int flags,
                                                        struct RoutingCalcRes *rcr);

struct sk_buff *self_defined__multicast_session_make_skb(struct sock *sk,
                                                         struct flowi4 *fl4,
                                                         struct sk_buff_head *queue,
                                                         struct inet_cork *cork,
                                                         struct RoutingCalcRes *rcr);


struct sk_buff *self_defined_selir_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            int getfrag(void *from, char *to, int offset,
                                                        int len, int odd, struct sk_buff *skb),
                                            void *from, int length, int transhdrlen,
                                            struct ipcm_cookie *ipc,
                                            struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr,
                                            u64 *encryption_time_elapsed);


struct sk_buff *self_defined__selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                             struct sk_buff_head *queue, struct inet_cork *cork,
                                             struct RoutingCalcRes *rcr,
                                             u64 *encryption_time_elapsed);

struct sk_buff *self_defined_fast_selir_make_skb(struct sock *sk,
                                                 struct flowi4 *fl4,
                                                 int getfrag(void *from, char *to, int offset,
                                                             int len, int odd, struct sk_buff *skb),
                                                 void *from, int length, int transhdrlen,
                                                 struct ipcm_cookie *ipc,
                                                 struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr,
                                                 u64 *make_skb_time_elapsed,
                                                 u64 *enc_time_elapsed);

struct sk_buff *self_defined__fast_selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                                  struct sk_buff_head *queue, struct inet_cork *cork,
                                                  struct RoutingCalcRes *rcr,
                                                  u64 *enc_time_elapsed);


struct sk_buff *self_defined_multicast_selir_make_skb(struct sock *sk,
                                                      struct flowi4 *fl4,
                                                      int getfrag(void *from, char *to, int offset,
                                                                  int len, int odd, struct sk_buff *skb),
                                                      void *from, int length, int transhdrlen,
                                                      struct ipcm_cookie *ipc,
                                                      struct inet_cork *cork, unsigned int flags,
                                                      struct RoutingCalcRes *rcr,
                                                      u64 *make_skb_time_elapsed);

struct sk_buff *self_defined_multicast_opt_make_skb(struct sock *sk,
                                                    struct flowi4 *fl4,
                                                    int getfrag(void *from, char *to, int offset,
                                                                int len, int odd, struct sk_buff *skb),
                                                    void *from, int length, int transhdrlen,
                                                    struct ipcm_cookie *ipc,
                                                    struct inet_cork *cork, unsigned int flags,
                                                    struct RoutingCalcRes *rcr,
                                                    u64 *make_skb_time_elapsed);

struct sk_buff *self_defined__multicast_selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                                       struct sk_buff_head *queue, struct inet_cork *cork,
                                                       struct RoutingCalcRes *rcr, int app_and_transport_length);

struct sk_buff *self_defined__multicast_opt_make_skb(struct sock *sk, struct flowi4 *fl4,
                                                     struct sk_buff_head *queue, struct inet_cork *cork,
                                                     struct RoutingCalcRes *rcr, int app_and_transport_length);


struct sk_buff *self_defined_multipath_selir_make_skb(struct sock *sk,
                                                      struct flowi4 *fl4,
                                                      int getfrag(void *from, char *to, int offset,
                                                                  int len, int odd, struct sk_buff *skb),
                                                      void *from, int length, int transhdrlen,
                                                      struct ipcm_cookie *ipc,
                                                      struct inet_cork *cork, unsigned int flags,
                                                      struct MultipathRes *mres,
                                                      u64 *make_skb_time_elapsed,
                                                      u64 *enc_time_elapsed);

struct sk_buff *self_defined__multipath_selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                                       struct sk_buff_head *queue, struct inet_cork *cork,
                                                       struct MultipathRes *mres,
                                                       int app_and_transport_length,
                                                       u64 *enc_time_elapsed);

struct sk_buff *self_defined_make_sec_path_mab_ack_skb(struct sk_buff *old_skb,
                                                       void *ack_content,
                                                       struct InterfaceTableEntry *ite,
                                                       int current_path_index);

#endif //LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
