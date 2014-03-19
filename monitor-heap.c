/*
 * Copyright (c) 2012 Nicira, Inc.
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

#include "monitor-aux.h"
#include "monitor-heap.h"

#include <stdlib.h>

static void put_node(struct monitor_heap *, struct monitor_heap_node *,
                     size_t i);
static void swap_nodes(struct monitor_heap *, size_t i, size_t j);
static bool float_up(struct monitor_heap *, size_t i);
static void float_down(struct monitor_heap *, size_t i);
static void float_up_or_down(struct monitor_heap *, size_t i);

/* Inserts 'node' into 'heap' with the specified 'priority'.
 *
 * This takes time O(lg n). */
void
monitor_heap_insert(struct monitor_heap *heap, struct monitor_heap_node *node,
                    uint64_t priority)
{
    monitor_heap_raw_insert(heap, node, priority);
    float_up(heap, node->idx);
}

/* Removes 'node' from 'heap'.
 *
 * This takes time O(lg n). */
void
monitor_heap_remove(struct monitor_heap *heap, struct monitor_heap_node *node)
{
    size_t i = node->idx;

    monitor_heap_raw_remove(heap, node);
    if (i <= heap->n) {
        float_up_or_down(heap, i);
    }
}

/* Changes the priority of 'node' (which must be in 'heap') to 'priority'.
 *
 * This takes time O(lg n). */
void
monitor_heap_change(struct monitor_heap *heap, struct monitor_heap_node *node,
                    uint64_t priority)
{
    monitor_heap_raw_change(node, priority);
    float_up_or_down(heap, node->idx);
}

/* Inserts 'node' into 'heap' with the specified 'priority', without
 * maintaining the heap invariant.
 *
 * After this call, monitor_heap_max() will no longer necessarily return the
 * maximum value in the heap, and MONITOR_HEAP_FOR_EACH will no longer
 * necessarily iterate in  heap level order, until the next call to
 * monitor_heap_rebuild(heap).
 *
 * This takes time O(1). */
void
monitor_heap_raw_insert(struct monitor_heap *heap,
                        struct monitor_heap_node *node, uint64_t priority)
{
    if (heap->n >= heap->allocated) {
        heap->allocated = heap->n == 0 ? 1 : 2 * heap->n;
        heap->array = monitor_realloc(heap->array,
                                      (heap->allocated + 1)
                                      * sizeof *heap->array);
    }

    put_node(heap, node, ++heap->n);
    node->priority = priority;
}

/* Removes 'node' from 'heap', without maintaining the heap invariant.
 *
 * After this call, monitor_heap_max() will no longer necessarily return the
 * maximum value in the heap, and MONITOR_HEAP_FOR_EACH will no longer
 * necessarily iterate in heap level order, until the next call to
 * monitor_heap_rebuild(heap).
 *
 * This takes time O(1). */
void
monitor_heap_raw_remove(struct monitor_heap *heap,
                        struct monitor_heap_node *node)
{
    size_t i = node->idx;
    if (i < heap->n) {
        put_node(heap, heap->array[heap->n], i);
    }
    heap->n--;
}

/* Rebuilds 'heap' to restore the heap invariant following a series of one or
 * more calls to monitor_heap_raw_*() functions.  (Otherwise this function need
 * not be called.)
 *
 * This takes time O(n) in the current size of the heap. */
void
monitor_heap_rebuild(struct monitor_heap *heap)
{
    size_t i;

    for (i = heap->n / 2; i >= 1; i--) {
        float_down(heap, i);
    }
}

static void
put_node(struct monitor_heap *heap, struct monitor_heap_node *node, size_t i)
{
    heap->array[i] = node;
    node->idx = i;
}

static void
swap_nodes(struct monitor_heap *heap, size_t i, size_t j)
{
    struct monitor_heap_node *old_i = heap->array[i];
    struct monitor_heap_node *old_j = heap->array[j];

    put_node(heap, old_j, i);
    put_node(heap, old_i, j);
}

static bool
float_up(struct monitor_heap *heap, size_t i)
{
    bool moved = false;
    size_t parent;

    for (; i > 1; i = parent) {
        parent = monitor_heap_parent__(i);
        if (heap->array[parent]->priority >= heap->array[i]->priority) {
            break;
        }
        swap_nodes(heap, parent, i);
        moved = true;
    }
    return moved;
}

static void
float_down(struct monitor_heap *heap, size_t i)
{
    while (!monitor_heap_is_leaf__(heap, i)) {
        size_t left = monitor_heap_left__(i);
        size_t right = monitor_heap_right__(i);
        size_t max = i;

        if (heap->array[left]->priority > heap->array[max]->priority) {
            max = left;
        }
        if (right <= heap->n
            && heap->array[right]->priority > heap->array[max]->priority) {
            max = right;
        }
        if (max == i) {
            break;
        }

        swap_nodes(heap, max, i);
        i = max;
    }
}

static void
float_up_or_down(struct monitor_heap *heap, size_t i)
{
    if (!float_up(heap, i)) {
        float_down(heap, i);
    }
}
