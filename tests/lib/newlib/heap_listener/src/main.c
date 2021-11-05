/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/libc_heap_listener.h>
#include <zephyr.h>
#include <ztest.h>

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

/* Function used by malloc() to obtain or free memory to the system */
extern void *_sbrk(intptr_t count);

static uintptr_t current_heap_end(void)
{
	return (uintptr_t)_sbrk(0);
}

static ptrdiff_t heap_difference;

static void heap_resized(void *old_heap_end, void *new_heap_end)
{
	heap_difference += ((char *)new_heap_end - (char *)old_heap_end);
}

static LIBC_HEAP_LISTENER_DEFINE(heap_listener, heap_resized);

/**
 * @brief Test that heap listener is notified when libc heap size changes.
 *
 * This test calls the malloc() and free() followed by malloc_trim() functions
 * and verifies that the heap listener is notified of allocating or returning
 * memory from the system.
 */
void test_alloc_and_trim(void)
{
	uintptr_t saved_heap_end;
	void *ptr;

	TC_PRINT("Allocating memory...\n");

	saved_heap_end = current_heap_end();
	ptr = malloc(4096);

	zassert_true(heap_difference > 0, "Heap increase not detected");
	zassert_equal(current_heap_end() - saved_heap_end, heap_difference,
		      "Heap increase not detected");

	TC_PRINT("Freeing memory...\n");

	heap_difference = 0;
	saved_heap_end = current_heap_end();
	free(ptr);
	malloc_trim(0);

	/*
	 * malloc_trim() may not free any memory to the system if there is not enough to free.
	 * Therefore, do not require that heap_difference < 0.
	 */
	zassert_equal(current_heap_end() - saved_heap_end, heap_difference,
		      "Heap decrease not detected");
}

void test_main(void)
{
	ztest_test_suite(newlib_heap_listener,
			 ztest_unit_test(test_alloc_and_trim));

	ztest_run_test_suite(newlib_heap_listener);
}
