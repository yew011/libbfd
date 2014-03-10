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

#ifndef BFD_AUX_H
#define BFD_AUX_H 1

/* The following functions and macros are used in bfd.c, but due to platform
 * differences, not implemented.  Users are responsible for bridging the gap
 * with the correct implementation.
 *
 *
 * Per-Thread Variable Macro
 * -------------------------
 *
 *     bfd_thread_local
 *
 *         To guarantee the thread-safety of the bfd_flag_to_str(), the
 *         per-thread char buffer is created using this macro for holding the
 *         parsed output.  Users are responsible for defining this macro.
 *         e.g. if you are using C11:
 *
 *             #include <thread.h>
 *             #define bfd_thread_local thread_local
 *
 *         Please note, the reentrancy is not guaranteed with this per-thread
 *         macro.
 *
 * Random Number Generation
 * ------------------------
 *
 *     bfd_get_random()
 *
 *         This should be a thread-safe function and returns a random unsigned
 *         integer, which will be used as the jitter in bfd_set_next_ts().
 *
 * Logging
 * -------
 *
 *     log-level macros:
 *
 *         Users are responsible for supporting the following log levels:
 *
 *         WARN   A low-level operation failed, but higher-level subsystems may
 *                be able to recover.  e.g. BFD control packet format error.
 *
 *         INFO   Information that may be useful in retrospect when
 *                investigating a problem.  e.g. POLL sequence start.
 *
 *         DBG    Information useful only to someone with intricate knowledge
 *                of the system, or that would commonly cause too-voluminous
 *                log output.  Log messages at this level are not logged by
 *                default.  e.g. send and recv of BFD control packets.
 *
 *     bfd_log(level, format, ...)
 *
 *         This function logs the content given in the Variadic Macros "..."
 *         with the specified 'level'.
 *
 *         To reduce logging overhead, users may also implement rate-limiting
 *         logic, like shown in the following pseudocode:
 *
 *             bfd_log(level, format, ...)
 *             {
 *                 if (bfd_should_log(level)) {
 *                     * logging code here. *
 *                 }
 *             }
 * */

#include "ovs-thread.h"
#include "random.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(bfd);

#define bfd_thread_local thread_local

#define bfd_get_random() random_uint32()

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 20);

/* Compatible with VLOG_LEVELS. */
enum bfd_log_levels {
    BFD_LOG_WARN = VLL_WARN,
    BFD_LOG_INFO = VLL_INFO,
    BFD_LOG_DBG = VLL_DBG
};

#define bfd_should_log(LEVEL) !vlog_should_drop(THIS_MODULE, LEVEL, &rl)

static void
bfd_log(enum bfd_log_levels level, const char *format, ...)
{
    if (bfd_should_log((enum vlog_level) level)) {
        va_list args;

        va_start(args, format);
        vlog_valist(THIS_MODULE, (enum vlog_level) level, format, args);
        va_end(args);
    }
}

#endif /* bfd-aux.h */
