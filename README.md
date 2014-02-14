libbfd
======
BFD GENERIC LIBRARY API:

#define BFD_VERSION 1
#define BFD_PACKET_LEN 24

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

/* Configures bfd using the 'setting'.  Returns 0 if successful, a positive
 * error number otherwise. */
enum bfd_error bfd_configure(struct bfd_session *, const struct bfd_setting *);

/* Returns the wakeup time of the bfd session. */
long long int bfd_wait(const struct bfd *);

/* Updates the bfd sessions status. e.g. bfd rx timeout and the
 * need for POLL sequence.  'now' is the current time in milliseconds. */
void bfd_run(struct bfd *, long long int now);

/* Queries the 'bfd''s status, the function will fill in the
 * 'bfd_status'. */
void bfd_get_status(const struct bfd *, struct bfd_status *)


/* For send/recv bfd control packets. */
/* Returns true if the bfd control packet should be sent for this bfd
 * session.  e.g. tx timeout or POLL flag is on.  'now' is the current
 * time in milliseconds. */
bool bfd_should_send_packet(const struct bfd *, long long int now);

/* Constructs the bfd packet in payload.  This function assumes that the
 * payload is properly aligned.  'now' is the current time in milliseconds. */
enum bfd_error bfd_put_packet(struct bfd *, void *p, size_t len,
                              long long int now);

/* Given the packet header entries, check if the packet is bfd control
 * packet. */
bool bfd_should_process_packet(const __be16 eth_type, const uint8_t ip_proto,
                               const __be16 udp_src);

/* Processes the bfd control packet in payload 'p'.  The payload length is
 * provided.  'now' is the current time in milliseoncds. */
enum bfd_error bfd_process_packet(struct bfd *, void *p, size_t len,
                                  long long int now);
