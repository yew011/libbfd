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

#include <config.h>

#include "monitor.h"
#include "monitor-aux.h"
#include "monitor-heap.h"
#include "monitor-hmap.h"

/* Converts the time in millisecond to heap priority. */
#define MSEC_TO_PRIO(TIME) (LLONG_MAX - (TIME))
/* Converts the heap priority to time in millisecond. */
#define PRIO_TO_MSEC(PRIO) (LLONG_MAX - (PRIO))

/* Heap for ordering 'struct mport's based on session wakeup time. */
static struct monitor_heap monitor_heap;

/* Hmap that contains all "struct mport"s. */
static struct monitor_hmap monitor_hmap =
    MONITOR_HMAP_INITIALIZER(&monitor_hmap);

/* Monitored port/interface. */
struct mport {
    struct monitor_hmap_node hmap_node;       /* In monitor_hmap. */
    struct monitor_heap_node heap_node;       /* In monitor_heap. */

    /* A private pointer that user can use to dereference the monitoring
     * session e.g. bfd/cfm. */
    const void *__ptr;
};


/* Tries finding and returning the 'mport' from the 'monitor_hmap' by using
 * the hash value of 'ptr'.  If there is no such 'mport', returns NULL. */
static struct mport *
mport_find(const void *ptr)
{
    struct mport *node;

    MONITOR_HMAP_FOR_EACH_WITH_HASH (node, hmap_node,
                                     monitor_hash_pointer(ptr),
                                     &monitor_hmap) {
        if (node->__ptr == ptr) {
            return node;
        }
    }
    return NULL;
}


/* Returns true if there is session in the 'monitor_hmap'. */
bool
monitor_has_session(void)
{
    return !monitor_hmap_is_empty(&monitor_hmap);
}

/* Creates a 'struct mport' for 'ptr' and registers the mport to the
 * 'monitor_heap' and 'monitor_hmap'. */
void
monitor_register_session(const void *ptr)
{
    struct mport *mport = mport_find(ptr);

    if (!mport) {
        mport = xzalloc(sizeof *mport);
        mport->__ptr = ptr;
        monitor_heap_insert(&monitor_heap, &mport->heap_node, 0);
        monitor_hmap_insert(&monitor_hmap, &mport->hmap_node,
                            hash_pointer(ptr, 0));
    }
}

/* Unregisters the 'struct mport' that contains the 'ptr' from
 * 'monitor_heap' and 'monitor_hmap', and deletes the 'struct mport'. */
void
monitor_unregister_session(const void *ptr)
{
    struct mport *mport = mport_find(ptr);

    if (mport) {
        monitor_heap_remove(&monitor_heap, &mport->heap_node);
        monitor_hmap_remove(&monitor_hmap, &mport->hmap_node);
        free(mport);
    }
}

/* Given the current time 'now', returns the '__ptr' of the 'struct mport'
 * of top-of-heap session, if 'now' is greater than the timeout of the
 * top-of-heap session.  Otherwise, returns NULL.  */
const void *
monitor_get_timedout_session(long long int now)
{
    long long int prio_now = MSEC_TO_PRIO(now);

    if (!monitor_heap_is_empty(&monitor_heap)
        && monitor_heap_max(&monitor_heap)->priority >= prio_now) {
        struct mport *mport;

        mport = object_containing(monitor_heap_max(&monitor_heap), mport,
                                  heap_node);
        return mport->__ptr;
    }

    return NULL;
}

/* Updates the priority of the heap node of the 'struct mport' which contains
 * 'ptr' based on the next wakeup time 'next'. */
int
monitor_update_session_timeout(const void *ptr, long long int next)
{
    struct mport *mport = mport_find(ptr);

    monitor_heap_change(&monitor_heap, &mport->heap_node, MSEC_TO_PRIO(next));

    return 0;
}

/* Returns the timeout in milliseconds of the session of top-of-heap
 * mport. */
long long int
monitor_next_timeout(void)
{
    if (monitor_heap_is_empty(&monitor_heap)) {
        return LLONG_MAX;
    } else {
        return PRIO_TO_MSEC(monitor_heap_max(&monitor_heap)->priority);
    }
}
