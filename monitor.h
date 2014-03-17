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

#ifndef MONITOR_H
#define MONITOR_H 1

#include <stdbool.h>

bool monitor_has_session(void);
void monitor_register_session(const void *iface);
void monitor_unregister_session(const void *iface);

bool monitor_has_timedout_session(long long int now);
const void * monitor_get_timedout_session(void);
int monitor_update_session_timeout(const void *iface, long long int next);
long long int monitor_next_timeout(void);

#endif /* monitor.h */
