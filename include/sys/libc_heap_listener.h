/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ZEPHYR_INCLUDE_SYS_LIBC_HEAP_LISTENER_H
#define ZEPHYR_INCLUDE_SYS_LIBC_HEAP_LISTENER_H

#include <toolchain.h>

struct z_libc_heap_listener {
	void (*heap_resized)(void *old_heap_end, void *new_heap_end);
};

/**
 * @brief Register libc heap event listener.
 *
 * The macro can be used to create a libc heap event listener, that is,
 * an object consisting of callback functions that will be invoked upon various
 * events related to libc heap usage, such as the heap resize.
 *
 * Sample usage:
 * @code
 * void on_heap_resized(void *old_heap_end, void *new_heap_end)
 * {
 *   LOG_INF("Heap end moved from %p to %p", old_heap_end, new_heap_end);
 * }
 *
 * LIBC_HEAP_LISTENER_DEFINE(my_heap_event_listener, on_heap_resized);
 * @endcode
 *
 * @param name Name of the listener object
 * @param heap_resized_cb Function that will be called when the heap is resized.
 */
#define LIBC_HEAP_LISTENER_DEFINE(name, heap_resized_cb)	\
	STRUCT_SECTION_ITERABLE(z_libc_heap_listener, name) = {	\
		.heap_resized = heap_resized_cb,		\
	}

#endif /* ZEPHYR_INCLUDE_SYS_LIBC_HEAP_LISTENER_H */
