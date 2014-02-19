/* Copyright (c) 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <config.h>

#include "bfd.h"
#include "bfd_thread-save.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include "byte-order.h"
#include "csum.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "ovs-thread.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "smap.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(bfd_ts);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct hmap all_bfds__ = HMAP_INITIALIZER(&all_bfds__);
static struct hmap *const all_bfds OVS_GUARDED_BY(mutex) = &all_bfds__;

struct bfd_ts {
    struct bfd *bfd;
    struct hmap_node node;
    char *name;
    uint32_t udp_src;
    uint32_t disc;
    atomic_int ref_cnt;
};

static struct bfd*
bfd_ts_find_by_name(const char *name)
{
    struct bfd_ts *ts;

    HMAP_FOR_EACH (ts, node, all_bfds) {
        if (!strcmp(ts->name, name)) {
            return ts->bfd;
        }
    }
    return NULL;
}

static void
bfd_put_details(struct ds *ds, const struct bfd *bfd)
{
    struct bfd_status status;
    bfd_get_status(bfd, &status);

    ds_put_format(ds, "\tForwarding: %s\n",
                  bfd_forwarding(bfd, time_msec()) ? "true" : "false");
    ds_put_format(ds, "\tDetect Multiplier: %d\n", bfd->mult);
    ds_put_format(ds, "\tConcatenated Path Down: %s\n",
                  bfd->cpath_down ? "true" : "false");
    ds_put_format(ds, "\tTX Interval: Approx %ums\n", status.tx_interval);
    ds_put_format(ds, "\tRX Interval: Approx %ums\n", status.rx_interval);
    ds_put_format(ds, "\tDetect Time: now %+lldms\n",
                  time_msec() - bfd->detect_time);
    ds_put_format(ds, "\tNext TX Time: now %+lldms\n",
                  time_msec() - bfd->next_tx);
    ds_put_format(ds, "\tLast TX Time: now %+lldms\n",
                  time_msec() - bfd->last_tx);

    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "\tLocal Flags: %s\n", bfd_flag_to_str(bfd->flags));
    ds_put_format(ds, "\tLocal Session State: %s\n",
                  bfd_state_to_str(bfd->state));
    ds_put_format(ds, "\tLocal Diagnostic: %s\n", bfd_diag_to_str(bfd->diag));
    ds_put_format(ds, "\tLocal Discriminator: 0x%"PRIx32"\n", bfd->disc);
    ds_put_format(ds, "\tLocal Minimum TX Interval: %dms\n",
                  status.bfd_min_tx);
    ds_put_format(ds, "\tLocal Minimum RX Interval: %ums\n", bfd->min_rx);

    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "\tRemote Flags: %s\n", bfd_flag_to_str(bfd->rmt_flags));
    ds_put_format(ds, "\tRemote Session State: %s\n",
                  bfd_state_to_str(bfd->rmt_state));
    ds_put_format(ds, "\tRemote Diagnostic: %s\n",
                  bfd_diag_to_str(bfd->rmt_diag));
    ds_put_format(ds, "\tRemote Discriminator: 0x%"PRIx32"\n", bfd->rmt_disc);
    ds_put_format(ds, "\tRemote Minimum TX Interval: %lldms\n",
                  bfd->rmt_min_tx);
    ds_put_format(ds, "\tRemote Minimum RX Interval: %lldms\n",
                  bfd->rmt_min_rx);
}

static void
bfd_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        struct bfd *bfd;

        bfd = bfd_find_by_name(argv[1]);
        if (!bfd) {
            unixctl_command_reply_error(conn, "no such bfd object");
            goto out;
        }
        bfd_put_details(&ds, bfd);
    } else {
        struct bfd_ts *ts;
        HMAP_FOR_EACH (ts, node, all_bfds) {
            ds_put_format(&ds, "---- %s ----\n", ts->name);
            bfd_put_details(&ds, ts->bfd);
        }
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    ovs_mutex_unlock(&mutex);
}

struct bfd *
bfd_ts_configure(struct bfd *bfd, const char *name, const struct smap *cfg)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static atomic_uint16_t udp_src = ATOMIC_VAR_INIT(0);

    struct bfd_ts *ts;
    struct bfd_setting setting;

    if (ovsthread_once_start(&once)) {
        unixctl_command_register("bfd/show", "[interface]", 0, 1,
                                 bfd_unixctl_show, NULL);
        ovsthread_once_done(&once);
    }

    if (!cfg || !smap_get_bool(cfg, "enable", false)) {
        ts = CONTAINER_OF(bfd, struct bfd_ts, bfd);
        bfd_ts_unref(ts);
        return NULL;
    }

    ovs_mutex_lock(&mutex);
    if (!bfd) {
        ts = xzalloc(sizeof *ts);
        bfd = xzalloc(sizeof *bfd);

        tx->bfd = bfd;
        ts->name = xstrdup(name);
        ts->disc = generate_discriminator();
        atomic_init(&ts->ref_cnt, 1);

        /* RFC 5881 section 4
         * The source port MUST be in the range 49152 through 65535.  The same
         * UDP source port number MUST be used for all BFD Control packets
         * associated with a particular session.  The source port number SHOULD
         * be unique among all BFD sessions on the system. */
        atomic_add(&udp_src, 1, &ts->udp_src);
        ts->udp_src = (ts->udp_src % 16384) + 49152;

        hmap_insert(all_bfds, &ts->node, ts->bfd->disc);
    } else {
        ts = CONTAINER_OF(bfd, struct bfd_ts, bfd);
    }


    memeset(&setting, 0, sizeof setting);
    setting.disc = ofport->bfd->disc;
    setting.mult = 3;
    setting.min_tx = smap_get_int(cfg, "min_tx", 100);
    setting.min_rx = smap_get_int(cfg, "min_rx", 100);
    setting.cpath_down = smap_get_bool(cfg, "cpath_down", false);
    setting.forward_if_rx_interval = smap_get_bool(cfg, "forwarding_if_rx",
                                                   0);
    setting.decay_min_rx = smap_get_bool(cfg, "decay_min_rx", 0);

    bfd_configure(ofport->bfd, &setting);
    ovs_mutex_unlock(&mutex);

    return bfd;
}

int
bfd_ts_get_status(struct bfd *bfd, struct smap *smap)
{
    struct bfd_status status;

    ovs_mutex_lock(&mutex);
    if (!bfd) {
        ovs_mutex_unlock(&mutex);
        return ENOENT;
    }

    bfd_get_status(bfd, &status);

    smap_add(smap, "forwarding", status.forwarding ? "true" : "false");
    smap_add(smap, "state", bfd_state_to_str(status.local_state));
    smap_add(smap, "diagnostic", bfd_diag_to_str(status.local_diag));
    smap_add_format(smap, "flap_count", "%"PRIu64, status.flap_count);

    if (status.local_state != STATE_DOWN) {
        smap_add(smap, "remote_state", bfd_state_to_str(status.rmt_state));
        smap_add(smap, "remote_diagnostic", bfd_diag_to_str(status.rmt_diag));
    }

    ovs_mutex_unlock(&mutex);
    return 0;
}

bool
bfd_ts_should_send_packet(struct bfd *bfd, long long int now)
{
    bool ret;

    ovs_mutex_lock(&mutex);
    ret = bfd_should_send_packet(bfd, now);
    ovs_mutex_unlock(&mutex);

    return ret;
}

void
bfd_ts_put_packet(struct bfd *bfd, struct ofpbuf *p,
                  uint8_t eth_src[ETH_ADDR_LEN],  long long int now)
{
    struct udp_header *udp;
    struct eth_header *eth;
    struct ip_header *ip;
    struct msg *msg;
    struct bfd_ts *ts = CONTAINER_OF(bfd, struct bfd_ts, bfd);

    ovs_mutex_lock(&mutex);

    ofpbuf_reserve(p, 2); /* Properly align after the ethernet header. */
    eth = ofpbuf_put_uninit(p, sizeof *eth);
    memcpy(eth->eth_src, eth_src, ETH_ADDR_LEN);
    memcpy(eth->eth_dst, bfd->eth_dst, ETH_ADDR_LEN);
    eth->eth_type = htons(ETH_TYPE_IP);

    ip = ofpbuf_put_zeros(p, sizeof *ip);
    ip->ip_ihl_ver = IP_IHL_VER(5, 4);
    ip->ip_tot_len = htons(sizeof *ip + sizeof *udp + sizeof *msg);
    ip->ip_ttl = 255;
    ip->ip_proto = IPPROTO_UDP;
    /* Use link local addresses: */
    put_16aligned_be32(&ip->ip_src, htonl(0xA9FE0100)); /* 169.254.1.0. */
    put_16aligned_be32(&ip->ip_dst, htonl(0xA9FE0101)); /* 169.254.1.1. */
    ip->ip_csum = csum(ip, sizeof *ip);

    udp = ofpbuf_put_zeros(p, sizeof *udp);
    udp->udp_src = htons(ts->udp_src);
    udp->udp_dst = htons(BFD_DEST_PORT);
    udp->udp_len = htons(sizeof *udp + sizeof *msg);


    bfd_put_packet(bfd, ofpbuf_put_uninit(p, sizeof *msg),
                   BFD_PACKET_LEN, now);
    ovs_mutex_unlock(&mutex);
}

void
bfd_ts_run(struct bfd *bfd, long long int now)
{
    ovs_mutex_lock(&mutex);
    bfd_run(bfd, now);
    ovs_mutex_unlock(&mutex);
}

bool
bfd_ts_forwarding(struct bfd *bfd, long long int now)
{
    bool ret;

    ovs_mutex_lock(&mutex);
    ret = bfd_forwarding(bfd, now);
    ovs_mutex_unlock(&mutex);

    return ret;
}

long long int
bfd_ts_wait(struct bfd *bfd)
{
    ovs_mutex_lock(&mutex);
    bfd_wait(bfd);
    ovs_mutex_unlock(&mutex);
}

bool
bfd_ts_should_process_packet(struct flow *flow)
{
    return bfd_should_process_packet(flow->dl_tye, flow->nw_proto,
                                     flow->tp_dst);
}

int
bfd_ts_process_packet(struct bfd *bfd, void *p, int len, long long int now)
{
    ovs_mutex_lock(&mutex);
    bfd_process_packet(bfd, p, len, now);
    ovs_mutex_unlock(&mutex);
}

void
bfd_ts_account_rx(struct bfd *bfd)
{
    ovs_mutex_lock(&mutex);
    bfd_account_rx(bfd);
    ovs_mutex_unlock(&mutex);
}

struct bfd *
bfd_ts_ref(struct bfd *bfd)
{
    struct bfd_ts *ts;

    if (bfd) {
        int orig;

        ts = CONTAINER_OF(bfd, struct bfd_ts, bfd);
        atomic_add(&ts->ref_cnt, 1, &orig);
        ovs_assert(orig > 0);
    }
    return bfd;
}

void
bfd_ts_unref(struct bfd *bfd)
{
    if (bfd) {
        int orig;
        struct bfd_ts *ts = CONTAINER_OF(bfd, struct bfd_ts, bfd);

        atomic_sub(&ts->ref_cnt, 1, &orig);
        ovs_assert(orig > 0);
        if (orig == 1) {
            ovs_mutex_lock(&mutex);
            hmap_remove(all_bfds, &ts->node);
            free(ts->name);
            free(bfd);
            free(ts);
            ovs_mutex_unlock(&mutex);
        }
    }
}
