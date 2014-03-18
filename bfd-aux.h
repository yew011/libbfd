/* Copyright (c) 2013, 2014 Nicira, Inc.
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
 * Random Number Generation
 * ------------------------
 *
 *     bfd_get_random()
 *
 *         This should be a thread-safe function and returns a random unsigned
 *         integer, which will be used as the jitter in bfd_set_next_ts().
 *
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

#endif /* bfd-aux.h */
