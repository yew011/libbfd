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

/* RFC 5880 Section 4.1
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       My Discriminator                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Your Discriminator                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Desired Min TX Interval                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Required Min RX Interval                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Required Min Echo RX Interval                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
struct msg {
    uint8_t vers_diag;    /* Version and diagnostic. */
    uint8_t flags;        /* 2bit State field followed by flags. */
    uint8_t mult;         /* Fault detection multiplier. */
    uint8_t length;       /* Length of this BFD message. */
    __be32 my_disc;       /* My discriminator. */
    __be32 your_disc;     /* Your discriminator. */
    __be32 min_tx;        /* Desired minimum tx interval. */
    __be32 min_rx;        /* Required minimum rx interval. */
    __be32 min_rx_echo;   /* Required minimum echo rx interval. */
};


/* Returns true if the interface on which bfd is running may be used to
 * forward traffic according to the BFD session state. */
static bool
bfd_forwarding(const struct bfd *bfd)
{
    return bfd->state == STATE_UP
        && bfd->rmt_diag != DIAG_PATH_DOWN
        && bfd->rmt_diag != DIAG_CPATH_DOWN
        && bfd->rmt_diag != DIAG_RCPATH_DOWN;
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
        bfd->poll_min_rx = bfd->cfg_min_rx;
        bfd->flags |= FLAG_POLL;
        bfd->next_tx = 0;
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
bfd_set_state(struct bfd *bfd, enum bfd_state state, enum bfd_diag diag)
{
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
    }
}


/* Configures bfd using the 'setting'.  Returns 0 if successful, a positive
 * error number otherwise. */
enum bfd_error
bfd_configure(struct bfd *bfd, const struct bfd_setting *setting)
{
    uint32_t min_tx, min_rx;
    uint8_t mult;
    bool need_poll = false;

    if (!bfd || !setting) {
        return BFD_EINVAL;
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
        return LLONG_MIN;
    }

    if (bfd->flags & FLAG_FINAL) {
        ret = 0;
    } else {
        ret = bfd->next_tx;
        if (bfd->state > STATE_DOWN) {
            ret = MIN(bfd->detect_time, ret);
        }
    }

    return ret;
}

/* Updates the bfd sessions status. e.g. bfd rx timeout.  And checks the
 * need for POLL sequence.  */
void
bfd_run(struct bfd *bfd, long long int now)
{
    if (!bfd) {
        return;
    }

    if (bfd->state > STATE_DOWN && now >= bfd->detect_time) {
        bfd_set_state(bfd, STATE_DOWN, DIAG_EXPIRED);
    }

    if (bfd->min_tx != bfd->cfg_min_tx
        || bfd->min_rx != bfd->cfg_min_rx) {
        bfd_poll(bfd);
    }
}

/* Queries the 'bfd''s status, the function will fill in the
 * 'bfd_status'. */
void
bfd_get_status(const struct bfd *bfd, struct bfd_status *s)
{
    if (!bfd || !s) {
        return;
    }

    s->forwarding = bfd_forwarding(bfd);
    s->local_state = bfd->state;
    s->local_diag = bfd->diag;
    s->rmt_state = bfd->rmt_state;
    s->rmt_diag = bfd->rmt_diag;
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
    struct msg *msg = p;

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
    struct msg *msg = p;

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
            bfd_set_state(bfd, STATE_DOWN, DIAG_RMT_DOWN);
        }
    } else {
        switch (bfd->state) {
        case STATE_DOWN:
            if (rmt_state == STATE_DOWN) {
                bfd_set_state(bfd, STATE_INIT, bfd->diag);
            } else if (rmt_state == STATE_INIT) {
                bfd_set_state(bfd, STATE_UP, bfd->diag);
            }
            break;
        case STATE_INIT:
            if (rmt_state > STATE_DOWN) {
                bfd_set_state(bfd, STATE_UP, bfd->diag);
            }
            break;
        case STATE_UP:
            if (rmt_state <= STATE_DOWN) {
                bfd_set_state(bfd, STATE_DOWN, DIAG_RMT_DOWN);
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
