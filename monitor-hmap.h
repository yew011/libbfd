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

#ifndef MONITOR_HMAP_H
#define MONITOR_HMAP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* A hash map node, to be embedded inside the data structure being mapped. */
struct monitor_hmap_node {
    uint32_t hash;                      /* Hash value. */
    struct monitor_hmap_node *next;     /* Next in linked list. */
};

/* A hash map. */
struct monitor_hmap {
    /* Must point to 'one' iff 'mask' == 0. */
    struct monitor_hmap_node **buckets;
    struct monitor_hmap_node *one;
    size_t mask;
    size_t n;
};

/* Initializer for an empty hash map. */
#define MONITOR_HMAP_INITIALIZER(HMAP) \
    { (struct monitor_hmap_node **const) &(HMAP)->one, NULL, 0, 0 }

static inline bool monitor_hmap_is_empty(const struct monitor_hmap *);

/* Adjusting capacity. */
void monitor_hmap_expand(struct monitor_hmap *);
void monitor_hmap_shrink(struct monitor_hmap *);

/* Insertion and deletion. */
static inline void monitor_hmap_insert(struct monitor_hmap *,
                                       struct monitor_hmap_node *,
                                       uint32_t hash);

static inline void monitor_hmap_insert_fast(struct monitor_hmap *,
                                            struct monitor_hmap_node *,
                                            uint32_t hash);
static inline void monitor_hmap_remove(struct monitor_hmap *,
                                       struct monitor_hmap_node *);

/* Search.
 *
 * MONITOR_HMAP_FOR_EACH_WITH_HASH iterates NODE over all of the nodes in
 * HMAP that have hash value equal to HASH.  MEMBER must be the name of the
 * 'struct monitor_hmap_node' member within NODE.
 *
 * The loop should not change NODE to point to a different node or insert or
 * delete nodes in HMAP (unless it "break"s out of the loop to terminate
 * iteration).
 *
 * HASH is only evaluated once.
 */
#define MONITOR_HMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, HMAP)            \
    for (assign_container(NODE, monitor_hmap_first_with_hash(HMAP, HASH),    \
                          MEMBER);                                           \
         NODE != object_containing(NULL, NODE, MEMBER);                      \
         assign_container(NODE, monitor_hmap_next_with_hash(&(NODE)->MEMBER),\
                          MEMBER))

static inline struct monitor_hmap_node *
    monitor_hmap_first_with_hash(const struct monitor_hmap *, uint32_t hash);
static inline struct monitor_hmap_node *
    monitor_hmap_next_with_hash(const struct monitor_hmap_node *);

/* Returns true if 'hmap' currently contains no nodes,
 * false otherwise. */
static inline bool
monitor_hmap_is_empty(const struct monitor_hmap *hmap)
{
    return hmap->n == 0;
}

/* Inserts 'node', with the given 'hash', into 'hmap'.  'hmap' is never
 * expanded automatically. */
static inline void
monitor_hmap_insert_fast(struct monitor_hmap *hmap,
                         struct monitor_hmap_node *node, uint32_t hash)
{
    struct monitor_hmap_node **bucket = &hmap->buckets[hash & hmap->mask];
    node->hash = hash;
    node->next = *bucket;
    *bucket = node;
    hmap->n++;
}

/* Inserts 'node', with the given 'hash', into 'hmap', and expands 'hmap' if
 * necessary to optimize search performance. */
static inline void
monitor_hmap_insert(struct monitor_hmap *hmap,
                    struct monitor_hmap_node *node, uint32_t hash)
{
    monitor_hmap_insert_fast(hmap, node, hash);
    if (hmap->n / 2 > hmap->mask) {
        monitor_hmap_expand(hmap);
    }
}

/* Removes 'node' from 'hmap'.  Does not shrink the hash table; call
 * monitor_hmap_shrink() directly if desired. */
static inline void
monitor_hmap_remove(struct monitor_hmap *hmap, struct monitor_hmap_node *node)
{
    struct monitor_hmap_node **bucket =
        &hmap->buckets[node->hash & hmap->mask];
    while (*bucket != node) {
        bucket = &(*bucket)->next;
    }
    *bucket = node->next;
    hmap->n--;
}

static inline struct monitor_hmap_node *
monitor_hmap_next_with_hash__(const struct monitor_hmap_node *node,
                             uint32_t hash)
{
    while (node != NULL && node->hash != hash) {
        node = node->next;
    }
    return (struct monitor_hmap_node *)node;
}

/* Returns the first node in 'hmap' with the given 'hash', or a null pointer if
 * no nodes have that hash value. */
static inline struct monitor_hmap_node *
monitor_hmap_first_with_hash(const struct monitor_hmap *hmap, uint32_t hash)
{
    return monitor_hmap_next_with_hash__(hmap->buckets[hash & hmap->mask],
                                         hash);
}

/* Returns the next node in the same hash map as 'node' with the same hash
 * value, or a null pointer if no more nodes have that hash value.
 *
 * If the hash map has been reallocated since 'node' was visited, some nodes
 * may be skipped; if new nodes with the same hash value have been added, they
 * will be skipped.  (Removing 'node' from the hash map does not prevent
 * calling this function, since node->next is preserved, although freeing
 * 'node' of course does.) */
static inline struct monitor_hmap_node *
monitor_hmap_next_with_hash(const struct monitor_hmap_node *node)
{
    return monitor_hmap_next_with_hash__(node->next, node->hash);
}

#ifdef  __cplusplus
}
#endif

#endif /* hmap.h */
