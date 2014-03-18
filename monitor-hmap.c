/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2014 Nicira, Inc.
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
 * limitations under the License.
 */

#include <config.h>
#include "monitor-aux.h"
#include "monitor-hmap.h"

#include <stdint.h>
#include <string.h>

/* Initializes 'hmap' as an empty hash table. */
static void
monitor_hmap_init(struct monitor_hmap *hmap)
{
    hmap->buckets = &hmap->one;
    hmap->one = NULL;
    hmap->mask = 0;
    hmap->n = 0;
}

/* Frees memory reserved by 'hmap'.  It is the client's responsibility to free
 * the nodes themselves, if necessary. */
static void
monitor_hmap_destroy(struct monitor_hmap *hmap)
{
    if (hmap && hmap->buckets != &hmap->one) {
        free(hmap->buckets);
    }
}

/* Adjusts 'hmap' to compensate for having moved position in memory (e.g. due
 * to realloc()). */
static void
monitor_hmap_moved(struct monitor_hmap *hmap)
{
    if (!hmap->mask) {
        hmap->buckets = &hmap->one;
    }
}

/* Exchanges hash maps 'a' and 'b'. */
static void
monitor_hmap_swap(struct monitor_hmap *a, struct monitor_hmap *b)
{
    struct monitor_hmap tmp = *a;
    *a = *b;
    *b = tmp;
    monitor_hmap_moved(a);
    monitor_hmap_moved(b);
}

static void
resize(struct monitor_hmap *hmap, size_t new_mask)
{
    struct monitor_hmap tmp;
    size_t i;

    ovs_assert(is_pow2(new_mask + 1));

    monitor_hmap_init(&tmp);
    if (new_mask) {
        tmp.buckets = monitor_zalloc(sizeof *tmp.buckets * (new_mask + 1));
        tmp.mask = new_mask;
        for (i = 0; i <= tmp.mask; i++) {
            tmp.buckets[i] = NULL;
        }
    }
    for (i = 0; i <= hmap->mask; i++) {
        struct monitor_hmap_node *node, *next;
        int count = 0;
        for (node = hmap->buckets[i]; node; node = next) {
            next = node->next;
            monitor_hmap_insert_fast(&tmp, node, node->hash);
            count++;
        }
    }
    monitor_hmap_swap(hmap, &tmp);
    monitor_hmap_destroy(&tmp);
}

static size_t
calc_mask(size_t capacity)
{
    size_t mask = capacity / 2;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
#if SIZE_MAX > UINT32_MAX
    mask |= mask >> 32;
#endif

    /* If we need to dynamically allocate buckets we might as well allocate at
     * least 4 of them. */
    mask |= (mask & 1) << 1;

    return mask;
}

/* Expands 'hmap', if necessary, to optimize the performance of searches. */
void
monitor_hmap_expand(struct monitor_hmap *hmap)
{
    size_t new_mask = calc_mask(hmap->n);
    if (new_mask > hmap->mask) {
        resize(hmap, new_mask);
    }
}

/* Shrinks 'hmap', if necessary, to optimize the performance of iteration. */
void
monitor_hmap_shrink(struct monitor_hmap *hmap)
{
    size_t new_mask = calc_mask(hmap->n);
    if (new_mask < hmap->mask) {
        resize(hmap, new_mask);
    }
}
