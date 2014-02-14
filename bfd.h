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
};

/* Used to configure a BFD session. */
struct bfd_setting {
    /* Local state variables. */
    uint32_t disc;                /* bfd.LocalDiscr. */
    uint8_t mult;                 /* bfd.DetectMult. */
    uint32_t min_tx;              /* bfd.DesiredMinTxInterval. */
    uint32_t min_rx;              /* bfd.RequiredMinRxInterval. */

    /* Open Vswitch specific settings. */
    bool cpath_down;              /* Set Concatenated Path Down. */
    bool forwarding_override;     /* Manual override of 'forwarding' status. */
    int forward_if_rx_interval;   /* How often to detect forward_if_rx. */
    int decay_min_rx;             /* bfd.min_rx is set to decay_min_rx when */
                                  /* in decay. */
};

/* BFD status. */
struct bfd_status {
    bool forwarding;              /* The liveness of bfd session. */
    uint8_t mult;                 /* bfd.DetectMult. */
    uint32_t tx_interval;         /* tx interval in use. */
    uint32_t rx_interval;         /* rx interval in use. */
    uint64_t flap_count;          /* Flap count of forwarding. */

    enum bfd_flags local_flags;   /* Flags sent on messages. */
    enum bfd_state local_state;   /* bfd.SessionState. */
    enum bfd_diag local_diag;     /* bfd.LocalDiag. */
    enum bfd_flags rmt_flags;     /* Flags last received. */
    enum bfd_state rmt_state;     /* bfd.RemoteSessionState. */
    enum bfd_diag rmt_diag;       /* Remote diagnostic. */
};

/* A BFD session.  Users are not permitted to directly access the variable
 * of this struct.  For BFD configuration, use the bfd_configure().  For
 * BFD status extraction, use the bfd_get_status(). */
struct bfd {
    /* Local state variables. */
    uint32_t disc;                /* bfd.LocalDiscr. */
    uint8_t mult;                 /* bfd.DetectMult. */
    enum bfd_state state;         /* bfd.SessionState. */
    enum bfd_diag diag;           /* bfd.LocalDiag. */
    enum bfd_flags flags;         /* Flags sent on messages. */
    uint32_t min_tx;              /* bfd.DesiredMinTxInterval. */
    uint32_t min_rx;              /* bfd.RequiredMinRxInterval. */
    uint32_t cfg_min_tx;          /* Configured minimum TX rate. */
    uint32_t cfg_min_rx;          /* Configured required minimum RX rate. */
    long long int detect_time;    /* RFC 5880 6.8.4 Detection time. */
    long long int last_tx;        /* Last TX time. */
    long long int next_tx;        /* Next TX time. */

    /* Remote side state variables. */
    uint32_t rmt_disc;            /* bfd.RemoteDiscr. */
    enum bfd_state rmt_state;     /* bfd.RemoteSessionState. */
    enum bfd_diag rmt_diag;       /* Remote diagnostic. */
    enum bfd_flags rmt_flags;     /* Flags last received. */
    long long int rmt_min_rx;     /* bfd.RemoteMinRxInterval. */
    long long int rmt_min_tx;     /* Remote minimum TX interval. */

    /* POLL sequence. */
    uint32_t poll_min_tx;         /* min_tx in POLL sequence. */
    uint32_t poll_min_rx;         /* min_rx in POLL sequence. */

    /* Open Vswitch specific features. */
    bool cpath_down;              /* Set Concatenated Path Down. */

    int forwarding_override;      /* Manual override of 'forwarding' status. */

    /* Equivalent to bfd demand mode. */
    bool last_forwarding;         /* Last calculation of forwarding flag. */
    int forward_if_rx_interval;   /* How often to detect forward_if_rx. */
    long long int forward_if_rx_detect_time;
    bool forward_if_rx_data;      /* Data packet received in last interval. */

    /* BFD decay feature is for reducing the */
    bool in_decay;                /* True when bfd is in decay. */
    int decay_min_rx;             /* bfd.min_rx is set to decay_min_rx when */
                                  /* in decay. */
    long long int decay_detect_time; /* Next decay detect time. */
    bool decay_rx_data;           /* Data packet received in last interval. */

    uint64_t flap_count;          /* Counts bfd forwarding flaps. */
};

enum bfd_error bfd_configure(struct bfd *, const struct bfd_setting *);
long long int bfd_wait(const struct bfd *);

void bfd_run(struct bfd *, long long int now);
void bfd_get_status(const struct bfd *, struct bfd_status *);
bool bfd_forwarding(const struct bfd *, long long int now);
void bfd_account_rx(struct bfd *);

bool bfd_should_send_packet(const struct bfd *, long long int now);
enum bfd_error bfd_put_packet(struct bfd *, void *, size_t len,
                              long long int now);
bool bfd_should_process_packet(const __be16 eth_type, const uint8_t ip_proto,
                               const __be16 udp_dst);
enum bfd_error bfd_process_packet(struct bfd *, void *, size_t len,
                                  long long now);

/* Helpers. */
const char * bfd_error_to_str(enum bfd_error error);
const char * bfd_flag_to_str(enum bfd_flags flags);
const char * bfd_state_to_str(enum bfd_state state);
const char * bfd_diag_to_str(enum bfd_diag diag);

#endif /* bfd.h */
