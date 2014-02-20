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

#include "bfd.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))


static bool
bfd_forwarding__(const struct bfd *bfd, long long int now)
{
    bool should_forward = false;

    if (bfd->forwarding_override) {
        return bfd->forwarding_override;
    }

    if (bfd->forward_if_rx_interval) {
        if (!bfd->forward_if_rx_detect_time) {
            should_forward = bfd->state == STATE_UP ? true : false;
        } else {
            should_forward = bfd->forward_if_rx_detect_time > now;
        }
    }

    return (bfd->state == STATE_UP
            || (bfd->forward_if_rx_interval && should_forward))
           && bfd->rmt_diag != DIAG_PATH_DOWN
           && bfd->rmt_diag != DIAG_CPATH_DOWN
           && bfd->rmt_diag != DIAG_RCPATH_DOWN;
}

/* If there is packet received, sets the 'forward_if_rx_detect_time'
 * to 'forward_if_rx_interval' away from now. */
static void
bfd_forward_if_rx(struct bfd *bfd, long long int now)
{
    if (bfd->forward_if_rx_data && bfd->forward_if_rx_interval) {
        bfd->forward_if_rx_detect_time = bfd->forward_if_rx_interval + now;
        bfd->forward_if_rx_data = false;
    }
}

/* Increments the 'flap_count' if there is a change in the
 * forwarding flag value. */
static void
bfd_check_forwarding_flap(struct bfd *bfd, long long int now)
{
    bool last_forwarding = bfd->last_forwarding;

    bfd->last_forwarding = bfd_forwarding__(bfd, now);
    if (bfd->last_forwarding != last_forwarding) {
        bfd->flap_count++;
    }
}

/* Decays the 'bfd->min_rx' to 'bfd->decay_min_rx' when number of packets
 * received during the 'decay_min_rx' interval is less than two time
 * of bfd control packets. */
static void
bfd_try_decay(struct bfd *bfd, long long int now)
{
    if (bfd->state == STATE_UP && bfd->decay_min_rx
        && now >= bfd->decay_detect_time) {
        uint32_t expect_rx = 2 * (bfd->decay_min_rx / bfd->min_rx + 1);

        bfd->in_decay = (bfd->decay_rx_count < expect_rx
                         && bfd->decay_min_rx > bfd->cfg_min_rx);
        bfd->decay_detect_time = bfd->decay_min_rx + now;
        bfd->decay_rx_count = 0;
    }
}

static long long int
bfd_min_tx(const struct bfd *bfd)
{
    /* RFC 5880 Section 6.8.3
     * When bfd.SessionState is not Up, the system MUST set
     * bfd.DesiredMinTxInterval to a value of not less than one second
     * (1,000,000 microseconds).  This is intended to ensure that the
     * bandwidth consumed by BFD sessions that are not Up is negligible,
     * particularly in the case where a neighbor may not be running BFD. */
    return (bfd->state == STATE_UP ? bfd->min_tx
            : MAX(bfd->min_tx, 1000));
}

static long long int
bfd_tx_interval(const struct bfd *bfd)
{
    long long int interval = bfd_min_tx(bfd);
    return MAX(interval, bfd->rmt_min_rx);
}

static long long int
bfd_rx_interval(const struct bfd *bfd)
{
    return MAX(bfd->min_rx, bfd->rmt_min_tx);
}

static void
bfd_set_next_tx(struct bfd *bfd)
{
    long long int interval = bfd_tx_interval(bfd);
    interval -= interval * (rand() % 26) / 100;
    bfd->next_tx = bfd->last_tx + interval;
}

static void
bfd_set_state(struct bfd *bfd, enum bfd_state state, enum bfd_diag diag,
              long long int now)
{
    if (bfd->cpath_down) {
        diag = DIAG_CPATH_DOWN;
    }

    if (bfd->state != state || bfd->diag != diag) {
        bfd->state = state;
        bfd->diag = diag;

        if (bfd->state <= STATE_DOWN) {
            bfd->rmt_state = STATE_DOWN;
            bfd->rmt_diag = DIAG_NONE;
            bfd->rmt_min_rx = 1;
            bfd->rmt_flags = 0;
            bfd->rmt_disc = 0;
            bfd->rmt_min_tx = 0;
        }

        if (bfd->state != STATE_UP && bfd->decay_min_rx) {
            bfd->min_rx = bfd->cfg_min_rx;
            bfd->in_decay = false;
            bfd->decay_rx_count = UINT32_MAX;
        }
    }

    bfd_check_forwarding_flap(bfd, now);
}

static bool
bfd_in_poll(const struct bfd *bfd)
{
    return (bfd->flags & FLAG_POLL) != 0;
}

static void
bfd_poll(struct bfd *bfd)
{
    if (bfd->state > STATE_DOWN && !bfd_in_poll(bfd)
        && !(bfd->flags & FLAG_FINAL)) {
        bfd->poll_min_tx = bfd->cfg_min_tx;
        bfd->poll_min_rx = bfd->in_decay ? bfd->decay_min_rx : bfd->cfg_min_rx;
        bfd->flags |= FLAG_POLL;
        bfd->next_tx = 0;
    }
}


/* Configures bfd using the 'setting'.  Returns 0 if successful, a positive
 * error number otherwise. */
enum bfd_error
bfd_configure(struct bfd *bfd, const struct bfd_setting *setting)
{
    uint32_t min_tx, min_rx;
    uint8_t mult;
    bool min_rx_changed = false;
    bool need_poll = false;

    if (!bfd || !setting) {
        return BFD_EINVAL;
    }

    if (bfd->state == STATE_ADMIN_DOWN) {
        bfd_set_state(bfd, STATE_DOWN, DIAG_NONE, 0);
    }

    if (bfd->disc != setting->disc) {
        bfd->disc = setting->disc;
    }

    mult = MAX(setting->mult, 3);
    if (bfd->mult != mult) {
        bfd->mult = mult;
    }

    min_tx = MAX(setting->min_tx, 100);
    if (bfd->cfg_min_tx != min_tx) {
        bfd->cfg_min_tx = min_tx;
        if (bfd->state != STATE_UP
            || (!bfd_in_poll(bfd) && bfd->cfg_min_tx < bfd->min_tx)) {
            bfd->min_tx = bfd->cfg_min_tx;
        }
        need_poll = true;
    }

    min_rx = MAX(setting->min_rx, 100);
    if (bfd->cfg_min_rx != min_rx) {
        bfd->cfg_min_rx = min_rx;
        if (bfd->state != STATE_UP
            || (!bfd_in_poll(bfd) && bfd->cfg_min_rx > bfd->min_rx)) {
            bfd->min_rx = bfd->cfg_min_rx;
        }
        min_rx_changed = true;
        need_poll = true;
    }

    if (bfd->cpath_down != setting->cpath_down) {
        bfd->cpath_down = setting->cpath_down;
        bfd_set_state(bfd, bfd->state, DIAG_NONE, 0);
        need_poll = true;
    }

    if (bfd->forwarding_override != setting->forwarding_override) {
        bfd->forwarding_override = setting->forwarding_override;
    }

    if (bfd->forward_if_rx_interval != setting->forward_if_rx_interval) {
        bfd->forward_if_rx_interval = setting->forward_if_rx_interval;
        bfd->forward_if_rx_detect_time = 0;
    }

    if (bfd->decay_min_rx != setting->decay_min_rx || min_rx_changed) {
        bfd->decay_min_rx = setting->decay_min_rx;
        bfd->in_decay = false;
        bfd->decay_rx_count = UINT32_MAX;
        bfd->decay_detect_time = 0;
        need_poll = true;
    }

    if (need_poll) {
        bfd_poll(bfd);
    }

    return BFD_PASS;
}

/* Returns the wakeup time of the bfd session. */
long long int
bfd_wait(const struct bfd *bfd)
{
    long long int ret;

    if (!bfd) {
        return LLONG_MAX;
    }

    if (bfd->flags & FLAG_FINAL) {
        ret = 0;
    } else {
        ret = bfd->next_tx;
        if (bfd->state > STATE_DOWN) {
            ret = MIN(bfd->detect_time, ret);
        }
        if (bfd->state == STATE_UP && bfd->decay_min_rx) {
            ret = MIN(bfd->decay_detect_time, ret);
        }
    }

    return ret;
}

/* Updates the bfd sessions status.  Checks decay and forward_if_rx.
 * Initiates the POLL sequence if needed. */
void
bfd_run(struct bfd *bfd, long long int now)
{
    bool old;

    if (!bfd) {
        return;
    }

    if (bfd->state > STATE_DOWN && now >= bfd->detect_time) {
        bfd_set_state(bfd, STATE_DOWN, DIAG_EXPIRED, now);
    }

    old = bfd->in_decay;
    bfd_try_decay(bfd, now);

    bfd_forward_if_rx(bfd, now);
    bfd_check_forwarding_flap(bfd, now);

    if (bfd->min_tx != bfd->cfg_min_tx
        || (!bfd->in_decay && bfd->min_rx != bfd->cfg_min_rx)
        || (bfd->in_decay && bfd->min_rx != bfd->decay_min_rx)
        || bfd->in_decay != old) {
        bfd_poll(bfd);
    }
}

/* Queries the 'bfd''s status, the function will fill in the
 * 'struct bfd_status'. */
void
bfd_get_status(const struct bfd *bfd, struct bfd_status *s)
{
    if (!bfd || !s) {
        return;
    }

    s->forwarding = bfd->last_forwarding;
    s->mult = bfd->mult;
    s->cpath_down = bfd->cpath_down;
    s->tx_interval = bfd_tx_interval(bfd);
    s->rx_interval = bfd_rx_interval(bfd);

    s->local_min_tx = bfd_min_tx(bfd);
    s->local_min_rx = bfd->min_rx;
    s->local_flags = bfd->flags;
    s->local_state = bfd->state;
    s->local_diag = bfd->diag;

    s->rmt_min_tx = bfd->rmt_min_tx;
    s->rmt_min_rx = bfd->rmt_min_rx;
    s->rmt_flags = bfd->rmt_flags;
    s->rmt_state = bfd->rmt_state;
    s->rmt_diag = bfd->rmt_diag;

    s->flap_count = bfd->flap_count;
}

/* Returns true if the interface on which bfd is running may be used to
 * forward traffic according to the BFD session state.  'now' is the
 * current time in milliseconds. */
bool
bfd_forwarding(const struct bfd *bfd, long long int now)
{
    return bfd_forwarding__(bfd, now);
}

/* Sets the corresponding flags to indicate that packet
 * is received from this monitored interface. */
void
bfd_account_rx(struct bfd *bfd, uint32_t n_pkt)
{
    if (bfd->forward_if_rx_interval && n_pkt) {
        bfd->forward_if_rx_data = true;
    }

    if (bfd->decay_min_rx && bfd->decay_rx_count != UINT32_MAX) {
        bfd->decay_rx_count += n_pkt;
    }
}

/* For send/recv bfd control packets. */
/* Returns true if the bfd control packet should be sent for this bfd
 * session.  e.g. tx timeout or POLL flag is on. */
bool
bfd_should_send_packet(const struct bfd *bfd, long long int now)
{
    return bfd->flags & FLAG_FINAL || now >= bfd->next_tx;
}

/* Constructs the bfd packet in payload.  This function assumes that the
 * payload is properly aligned. */
enum bfd_error
bfd_put_packet(struct bfd *bfd, void *p, size_t len, long long int now)
{
    long long int min_tx, min_rx;
    struct bfd_msg *msg = p;

    if (!bfd || !p || len < BFD_PACKET_LEN) {
        return BFD_EINVAL;
    }

    /* RFC 5880 Section 6.5
     * A BFD Control packet MUST NOT have both the Poll (P) and Final (F) bits
     * set. */
    if ((bfd->flags & FLAG_POLL) && (bfd->flags & FLAG_FINAL)) {
        return BFD_EPOLL;
    }

    msg->vers_diag = (BFD_VERSION << 5) | bfd->diag;
    msg->flags = (bfd->state & STATE_MASK) | bfd->flags;

    msg->mult = bfd->mult;
    msg->length = sizeof *bfd;
    msg->my_disc = htonl(bfd->disc);
    msg->your_disc = htonl(bfd->rmt_disc);
    msg->min_rx_echo = htonl(0);

    if (bfd_in_poll(bfd)) {
        min_tx = bfd->poll_min_tx;
        min_rx = bfd->poll_min_rx;
    } else {
        min_tx = bfd_min_tx(bfd);
        min_rx = bfd->min_rx;
    }

    msg->min_tx = htonl(min_tx * 1000);
    msg->min_rx = htonl(min_rx * 1000);

    bfd->flags &= ~FLAG_FINAL;

    bfd->last_tx = now;
    bfd_set_next_tx(bfd);

    return BFD_PASS;
}

/* Given the packet header entries, check if the packet is bfd control
 * packet. */
bool
bfd_should_process_packet(const __be16 eth_type, const uint8_t ip_proto,
                          const __be16 udp_dst)
{
    return (eth_type == htons(0x0800) /* IP. */
            && ip_proto == 17         /* UDP. */
            && udp_dst == htons(3784));
}

/* Processes the bfd control packet in payload 'p'.  The payload length is
 * provided. */
enum bfd_error
bfd_process_packet(struct bfd *bfd, void *p, size_t len, long long int now)
{
    uint32_t rmt_min_rx, pkt_your_disc;
    enum bfd_state rmt_state;
    enum bfd_flags flags;
    uint8_t version;
    struct bfd_msg *msg = p;

    if (!bfd || !p || len < BFD_PACKET_LEN) {
        return BFD_EINVAL;
    }

    /* This function is designed to follow section RFC 5880 6.8.6 closely. */

    /* RFC 5880 Section 6.8.6
     * If the Length field is greater than the payload of the encapsulating
     * protocol, the packet MUST be discarded.
     *
     * Note that we make this check implicity.  Above we use ofpbuf_at() to
     * ensure that there are at least BFD_PACKET_LEN bytes in the payload of
     * the encapsulating protocol.  Below we require msg->length to be exactly
     * BFD_PACKET_LEN bytes. */

    flags = msg->flags & FLAGS_MASK;
    rmt_state = msg->flags & STATE_MASK;
    version = msg->vers_diag >> VERS_SHIFT;

    if (version != BFD_VERSION) {
        goto err;
    }

    /* Technically this should happen after the length check. We don't support
     * authentication however, so it's simpler to do the check first. */
    if (flags & FLAG_AUTH) {
        goto err;
    }

    if (msg->length != BFD_PACKET_LEN) {
        if (msg->length < BFD_PACKET_LEN) {
            goto err;
        }
    }

    if (!msg->mult) {
        goto err;
    }

    if (flags & FLAG_MULTIPOINT) {
        goto err;
    }

    if (!msg->my_disc) {
        goto err;
    }

    pkt_your_disc = ntohl(msg->your_disc);
    if (pkt_your_disc) {
        /* Technically, we should use the your discriminator field to figure
         * out which 'struct bfd' this packet is destined towards.  That way a
         * bfd session could migrate from one interface to another
         * transparently.  This doesn't fit in with the OVS structure very
         * well, so in this respect, we are not compliant. */
       if (pkt_your_disc != bfd->disc) {
           goto err;
       }
    } else if (rmt_state > STATE_DOWN) {
        goto err;
    }

    bfd->rmt_disc = ntohl(msg->my_disc);
    bfd->rmt_state = rmt_state;
    bfd->rmt_flags = flags;
    bfd->rmt_diag = msg->vers_diag & DIAG_MASK;

    if (flags & FLAG_FINAL && bfd_in_poll(bfd)) {
        bfd->min_tx = bfd->poll_min_tx;
        bfd->min_rx = bfd->poll_min_rx;
        bfd->flags &= ~FLAG_POLL;
    }

    if (flags & FLAG_POLL) {
        /* RFC 5880 Section 6.5
         * When the other system receives a Poll, it immediately transmits a
         * BFD Control packet with the Final (F) bit set, independent of any
         * periodic BFD Control packets it may be sending
         * (see section 6.8.7). */
        bfd->flags &= ~FLAG_POLL;
        bfd->flags |= FLAG_FINAL;
    }

    rmt_min_rx = MAX(ntohl(msg->min_rx) / 1000, 1);
    if (bfd->rmt_min_rx != rmt_min_rx) {
        bfd->rmt_min_rx = rmt_min_rx;
        if (bfd->next_tx) {
            bfd_set_next_tx(bfd);
        }
    }

    bfd->rmt_min_tx = MAX(ntohl(msg->min_tx) / 1000, 1);
    bfd->detect_time = bfd_rx_interval(bfd) * bfd->mult + now;

    if (bfd->state == STATE_ADMIN_DOWN) {
        goto out;
    }

    if (rmt_state == STATE_ADMIN_DOWN) {
        if (bfd->state != STATE_DOWN) {
            bfd_set_state(bfd, STATE_DOWN, DIAG_RMT_DOWN, now);
        }
    } else {
        switch (bfd->state) {
        case STATE_DOWN:
            if (rmt_state == STATE_DOWN) {
                bfd_set_state(bfd, STATE_INIT, bfd->diag, now);
            } else if (rmt_state == STATE_INIT) {
                bfd_set_state(bfd, STATE_UP, bfd->diag, now);
            }
            break;
        case STATE_INIT:
            if (rmt_state > STATE_DOWN) {
                bfd_set_state(bfd, STATE_UP, bfd->diag, now);
            }
            break;
        case STATE_UP:
            if (rmt_state <= STATE_DOWN) {
                bfd_set_state(bfd, STATE_DOWN, DIAG_RMT_DOWN, now);
            }
            break;
        case STATE_ADMIN_DOWN:
        default:
            break;
        }
    }

out:
    return BFD_PASS;

err:
    return BFD_EMSG;
}

/* Helpers. */
/* Converts the bfd error code to string. */
const char *
bfd_error_to_str(enum bfd_error error)
{
    switch (error) {
    case BFD_PASS: return "No Error";
    case BFD_EINVAL: return "Invalid Arguments";
    case BFD_EPOLL: return "Both POLL And FINAL Set";
    case BFD_EMSG: return "Bad Control Packet";
    default: return "Not An Error Code";
    }
}

/* Converts the bfd flags to string. */
const char *
bfd_flag_to_str(enum bfd_flags flags)
{
    static char flag_str[128];

    if (!flags) {
        return "none";
    }

    memset(flag_str, 0, sizeof *flag_str);

    if (flags & FLAG_MULTIPOINT) {
        strcat(flag_str, "multipoint ");
    }

    if (flags & FLAG_DEMAND) {
        strcat(flag_str, "demand ");
    }

    if (flags & FLAG_AUTH) {
        strcat(flag_str, "auth");
    }

    if (flags & FLAG_CTL) {
        strcat(flag_str, "ctl");
    }

    if (flags & FLAG_FINAL) {
        strcat(flag_str, "final");
    }

    if (flags & FLAG_POLL) {
        strcat(flag_str, "poll");
    }

    return flag_str;
}

/* Converts the bfd state code to string. */
const char *
bfd_state_to_str(enum bfd_state state)
{
    switch (state) {
    case STATE_ADMIN_DOWN: return "admin_down";
    case STATE_DOWN: return "down";
    case STATE_INIT: return "init";
    case STATE_UP: return "up";
    default: return "invalid";
    }
}

/* Converts the bfd diag to string. */
const char *
bfd_diag_to_str(enum bfd_diag diag) {
    switch (diag) {
    case DIAG_NONE: return "No Diagnostic";
    case DIAG_EXPIRED: return "Control Detection Time Expired";
    case DIAG_ECHO_FAILED: return "Echo Function Failed";
    case DIAG_RMT_DOWN: return "Neighbor Signaled Session Down";
    case DIAG_FWD_RESET: return "Forwarding Plane Reset";
    case DIAG_PATH_DOWN: return "Path Down";
    case DIAG_CPATH_DOWN: return "Concatenated Path Down";
    case DIAG_ADMIN_DOWN: return "Administratively Down";
    case DIAG_RCPATH_DOWN: return "Reverse Concatenated Path Down";
    default: return "Invalid Diagnostic";
    }
}
