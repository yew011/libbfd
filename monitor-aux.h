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

/* The following functions and macros are used in monitor.c, but due to platform
 * differences, not implemented.  Users are responsible for bridging the gap
 * with the correct implementation.
 *
 *
 * Dynamic Memory Allocation
 * -------------------------
 *
 *     void *monitor_zalloc(size_t size);
 *     void *monitor_realloc(size_t size);
 *     void monitor_free(void *ptr);
 *
 *         Similiar to the memory allocation function in C standard library.
 *
 *
 * Containing Object Extraction
 * ----------------------------
 *
 *     OBJECT_CONTAINING(OPINTER, OBJECT, MEMBER):
 *
 *         Given POINTER, the address of the given MEMBER within an object of
 *         the type that OBJECT points to, returns OBJECT as an assignment-
 *         compatible pointer type (either the correct pointer type or
 *         "void *").  OBJECT must be an lvalue.
 *
 *         Please refer to "lib/util.h" in Open Vswitch project for the
 *         implementation of this macro.
 *
 *
 * Hashing Functions
 * -----------------
 *
 *     uint32_t hash_pointer(void *ptr):
 *
 *         Hash the pointer 'ptr' into uint32_t number.
 *
 *
 * */
