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

#ifndef BFD_TS_H
#define BFD_TS_H 1

#include <stdbool.h>
#include <inttypes.h>

struct bfd;
struct flow;
struct ofpbuf;
struct smap;

struct bfd * bfd_ts_configure(struct bfd *bfd, const char *name, const struct smap *cfg);

int bfd_ts_get_status(struct bfd *bfd, struct smap *smap);

bool bfd_ts_should_send_packet(struct bfd *bfd, long long int now);

void bfd_ts_put_packet(struct bfd *bfd, struct ofpbuf *p,
                       uint8_t eth_src[ETH_ADDR_LEN],  long long int now);

void bfd_ts_run(struct bfd *bfd, long long int now);

bool bfd_ts_forwarding(struct bfd *bfd, long long int now);

long long int bfd_ts_wait(struct bfd *bfd);

bool bfd_ts_should_process_packet(struct flow *flow);

int bfd_ts_process_packet(struct bfd *bfd, void *p, int len, long long int now);

void bfd_ts_account_rx(struct bfd *bfd);

struct bfd * bfd_ts_ref(struct bfd *bfd);

void bfd_ts_unref(struct bfd *bfd);


#endif /* bfd_thread-save.h */
