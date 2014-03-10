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

#include "hash.h"
#include "heap.h"
#include "hmap.h"
#include "util.h"

/* Converts the time in millisecond to heap priority. */
#define MSEC_TO_PRIO(TIME) (LLONG_MAX - (TIME))
/* Converts the heap priority to time in millisecond. */
#define PRIO_TO_MSEC(PRIO) (LLONG_MAX - (PRIO))

/* Heap for ordering 'struct mport's based on session wakeup time. */
static struct heap monitor_heap;

/* Hmap that contains all "struct mport"s. */
static struct hmap monitor_hmap = HMAP_INITIALIZER(&monitor_hmap);

/* Monitored port/interface. */
struct mport {
    struct hmap_node hmap_node;       /* In monitor_hmap. */
    struct heap_node heap_node;       /* In monitor_heap. */

    /* Anything that user can use to identify the interface owning the
     * monitored session.  For example, 'iface' can be the pointer to the
     * actual monitored 'strcut iface' which contains reference to bfd/cfm
     * object. */
    void *iface;
};


/* Tries finding and returning the 'mport' from the monitor_hmap by using
 * the hash value of 'iface'.  If there is no such 'mport', returns NULL. */
static struct mport *
mport_find(const void *iface)
{
    struct mport *node;

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash_pointer(iface, 0),
                             &monitor_hmap) {
        if (node->iface == iface) {
            return node;
        }
    }
    return NULL;
}


/* Creates a 'struct mport' and registers the mport to the 'monitor_heap'
 * and 'monitor_hmap'.  Returns 0 if successful, otherwise, a positive
 * error number. */
int
monitor_register_session(void *iface)
{
    struct mport *mport = mport_find(iface);

    mport = xzalloc(sizeof *mport);
    mport->iface = iface;
    heap_insert(&monitor_heap, &mport->heap_node, 0);
    hmap_insert(&monitor_hmap, &mport->hmap_node, hash_pointer(iface, 0));

    return 0;
}

/* Unregisters the 'struct mport' that contains the 'iface' from
 * 'monitor_heap' and 'monitor_hmap', and deletes the 'struct mport'.
 *  Returns 0 if successful, otherwise, a positive error number. */
int
monitor_unregister_session(void *iface)
{
    struct mport *mport = mport_find(iface);

    heap_remove(&monitor_heap, &mport->heap_node);
    hmap_remove(&monitor_hmap, &mport->hmap_node);
    free(mport);

    return 0;
}

/* Returns true if the top-of-heap session has timed out. */
bool
monitor_has_timedout_session(long long int now)
{
    long long int prio_now = MSEC_TO_PRIO(now);

    if (!heap_is_empty(&monitor_heap)
        && heap_max(&monitor_heap)->priority >= prio_now) {
        return true;
    }

    return false;
}

/* Returns the 'iface' of the 'mport' of the top-of-heap session. */
void *
monitor_get_timedout_session(void)
{
    struct mport *mport;

    if (heap_is_empty(&monitor_heap)) {
        return NULL;
    }
    mport = OBJECT_CONTAINING(heap_max(&monitor_heap), mport, heap_node);

    return mport->iface;
}

/* Updates the priority of the heap node of the 'struct mport' which contains
 * 'iface' based on the next wakeup time 'next'. */
int
monitor_update_session_timeout(const void *iface, long long int next)
{
    struct mport *mport = mport_find(iface);

    heap_change(&monitor_heap, &mport->heap_node, MSEC_TO_PRIO(next));

    return 0;
}

/* Returns the timeout in miiliseconds of the session of top-of-heap
 * mport. */
long long int
monitor_next_timeout(void)
{
    if (heap_is_empty(&monitor_heap)) {
        return LLONG_MAX;
    } else {
        return PRIO_TO_MSEC(heap_max(&monitor_heap)->priority);
    }
}
