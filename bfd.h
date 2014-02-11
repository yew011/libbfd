/* Copyright (c) 2014 Nicira, Inc.
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

#ifndef BFD_H
#define BFD_H 1

#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BFD_VERSION 1
#define BFD_PACKET_LEN 24

#define VERS_SHIFT 5
#define DIAG_MASK 0x1f
#define STATE_MASK 0xC0
#define FLAGS_MASK 0x3f

#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

enum bfd_flags {
    FLAG_MULTIPOINT = 1 << 0,
    FLAG_DEMAND = 1 << 1,
    FLAG_AUTH = 1 << 2,
    FLAG_CTL = 1 << 3,
    FLAG_FINAL = 1 << 4,
    FLAG_POLL = 1 << 5
};

enum bfd_state {
    STATE_ADMIN_DOWN = 0 << 6,
    STATE_DOWN = 1 << 6,
    STATE_INIT = 2 << 6,
    STATE_UP = 3 << 6
};

enum bfd_diag {
    DIAG_NONE = 0,                /* No Diagnostic. */
    DIAG_EXPIRED = 1,             /* Control Detection Time Expired. */
    DIAG_ECHO_FAILED = 2,         /* Echo Function Failed. */
    DIAG_RMT_DOWN = 3,            /* Neighbor Signaled Session Down. */
    DIAG_FWD_RESET = 4,           /* Forwarding Plane Reset. */
    DIAG_PATH_DOWN = 5,           /* Path Down. */
    DIAG_CPATH_DOWN = 6,          /* Concatenated Path Down. */
    DIAG_ADMIN_DOWN = 7,          /* Administratively Down. */
    DIAG_RCPATH_DOWN = 8          /* Reverse Concatenated Path Down. */
};

enum bfd_error {
    BFD_PASS = 0,                 /* No error. */
    BFD_EINVAL = 1,               /* Invalid arguments. */
    BFD_EPOLL = 2,                /* bfd poll and final flags are both on. */
    BFD_EMSG = 3                  /* bfd control packet error. */
}

/* Used to configure a BFD session. */
struct bfd_setting {
    /* Local state variables. */
    uint32_t disc;                /* bfd.LocalDiscr. */
    uint8_t mult;                 /* bfd.DetectMult. */
    uint32_t min_tx;              /* bfd.DesiredMinTxInterval. */
    uint32_t min_rx;              /* bfd.RequiredMinRxInterval. */
};

/* BFD status. */
struct bfd_status {
    bool forwarding;              /* The liveness of bfd session. */
    enum state local_state;       /* bfd.SessionState. */
    enum diag local_diag;         /* bfd.LocalDiag. */
    enum state rmt_state;         /* bfd.RemoteSessionState. */
    enum diag rmt_diag;           /* Remote diagnostic. */
};

/* A BFD session.  Users are not permitted to directly access the variable
 * of this struct.  For BFD configuration, use the bfd_configure().  For
 * BFD status extraction, use the bfd_get_status(). */
struct bfd {
    /* Local state variables. */
    uint32_t disc;                /* bfd.LocalDiscr. */
    uint8_t mult;                 /* bfd.DetectMult. */
    enum state state;             /* bfd.SessionState. */
    enum diag diag;               /* bfd.LocalDiag. */
    enum flags flags;             /* Flags sent on messages. */
    uint32_t min_tx;              /* bfd.DesiredMinTxInterval. */
    uint32_t min_rx;              /* bfd.RequiredMinRxInterval. */
    uint32_t cfg_min_tx;          /* Configured minimum TX rate. */
    uint32_t cfg_min_rx;          /* Configured required minimum RX rate. */
    long long int detect_time;    /* RFC 5880 6.8.4 Detection time. */
    long long int last_tx;        /* Last TX time. */
    long long int next_tx;        /* Next TX time. */

    /* Remote side state variables. */
    uint32_t rmt_disc;            /* bfd.RemoteDiscr. */
    enum state rmt_state;         /* bfd.RemoteSessionState. */
    enum diag rmt_diag;           /* Remote diagnostic. */
    enum flags rmt_flags;         /* Flags last received. */
    long long int rmt_min_rx;     /* bfd.RemoteMinRxInterval. */
    long long int rmt_min_tx;     /* Remote minimum TX interval. */

    /* POLL sequence. */
    uint32_t poll_min_tx;         /* min_tx in POLL sequence. */
    uint32_t poll_min_rx;         /* min_rx in POLL sequence. */
};

enum bfd_error bfd_configure(struct bfd *, const struct bfd_setting *);
long long int bfd_wait(const struct bfd *);

void bfd_run(struct bfd *, long long int now);
void bfd_get_status(const struct bfd *, struct bfd_status *);

bool bfd_should_send_packet(const struct bfd *, long long int now);
enum bfd_error bfd_put_packet(struct bfd *, void *, size_t len,
                              long long int now);
bool bfd_should_process_packet(const __be16 eth_type, const uint8_t ip_proto,
                               const __be16 udp_dst);
enum bfd_error bfd_process_packet(struct bfd *, void *, size_t len,
                                  long long now);

#endif /* bfd.h */
