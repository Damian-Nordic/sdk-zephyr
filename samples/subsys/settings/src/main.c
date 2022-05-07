/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "settings/settings.h"

#include <errno.h>
#include <sys/printk.h>

void main(void)
{
	int err = settings_subsys_init();

	if (err) {
		printk("ERROR: %d", err);
	}
}
