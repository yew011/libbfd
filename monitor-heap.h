/*
 * Copyright (c) 2012, 2013 Nicira, Inc.
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

#ifndef MONITOR_HEAP_H
#define MONITOR_HEAP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A heap node, to be embedded inside the data structure in the heap. */
struct monitor_heap_node {
    size_t idx;
    uint64_t priority;
};

/* A max-heap. */
struct monitor_heap {
    /* Data in elements 1...n, element 0 unused. */
    struct monitor_heap_node **array;
    size_t n;                   /* Number of nodes currently in the heap. */
    size_t allocated;           /* Max 'n' before 'array' must be enlarged. */
};

/* Insertion and deletion. */
void monitor_heap_insert(struct monitor_heap *, struct monitor_heap_node *,
                         uint64_t priority);
void monitor_heap_change(struct monitor_heap *, struct monitor_heap_node *,
                         uint64_t priority);
void monitor_heap_remove(struct monitor_heap *, struct monitor_heap_node *);

/* Maximum.  */
static inline struct monitor_heap_node *
    monitor_heap_max(const struct monitor_heap *);

/* The "raw" functions below do not preserve the heap invariants.  After you
 * call them, monitor_heap_max() will not necessarily return the right value
 * until you subsequently call monitor_heap_rebuild(). */
void monitor_heap_raw_insert(struct monitor_heap *, struct monitor_heap_node *,
                             uint64_t priority);
static inline void monitor_heap_raw_change(struct monitor_heap_node *,
                                           uint64_t priority);
void monitor_heap_raw_remove(struct monitor_heap *,
                             struct monitor_heap_node *);
void monitor_heap_rebuild(struct monitor_heap *);


/* Returns the index of the node that is the parent of the node with the given
 * 'idx' within a heap. */
static inline size_t
monitor_heap_parent__(size_t idx)
{
    return idx / 2;
}

/* Returns the index of the node that is the left child of the node with the
 * given 'idx' within a heap. */
static inline size_t
monitor_heap_left__(size_t idx)
{
    return idx * 2;
}

/* Returns the index of the node that is the right child of the node with the
 * given 'idx' within a heap. */
static inline size_t
monitor_heap_right__(size_t idx)
{
    return idx * 2 + 1;
}

/* Returns true if 'idx' is the index of a leaf node in 'heap', false
 * otherwise. */
static inline bool
monitor_heap_is_leaf__(const struct monitor_heap *heap, size_t idx)
{
    return monitor_heap_left__(idx) > heap->n;
}

/* Returns the number of elements in 'heap'. */
static inline size_t
monitor_heap_count(const struct monitor_heap *heap)
{
    return heap->n;
}

/* Returns true if 'heap' is empty, false if it contains at least one
 * element. */
static inline bool
monitor_heap_is_empty(const struct monitor_heap *heap)
{
    return heap->n == 0;
}

/* Returns the largest element in 'heap'.
 *
 * The caller must ensure that 'heap' contains at least one element.
 *
 * The return value may be wrong (i.e. not the maximum element but some other
 * element) if a monitor_heap_raw_*() function has been called without a later
 * call to monitor_heap_rebuild(). */
static inline struct monitor_heap_node *
monitor_heap_max(const struct monitor_heap *heap)
{
    return heap->array[1];
}

/* Changes the priority of 'node' (which must be in 'heap') to 'priority'.
 *
 * After this call, monitor_heap_max() will no longer necessarily return the
 * maximum value in the heap, and MONITOR_HEAP_FOR_EACH will no longer
 * necessarily iterate in heap level order, until the next call to
 * monitor_heap_rebuild(heap).
 *
 * This takes time O(1). */
static inline void
monitor_heap_raw_change(struct monitor_heap_node *node, uint64_t priority)
{
    node->priority = priority;
}

#endif /* heap.h */
