
#ifndef SETTINGS_PROFILER_H
#define SETTINGS_PROFILER_H

#include <stdint.h>
#include <zephyr.h>

enum settings_counter_id { CNT_NVS_ATE_READ, CNT_MAX };
static const char *const settings_counter_name[] = { "NVS ate read" };

enum settings_timer_id { TM_READ, TM_NVS_KEY_READ, TM_NVS_VALUE_FIND, TM_NVS_VALUE_READ, TM_MAX };
static const char *const settings_timer_name[] = { "Setting read", "NVS key read",
						   "NVS value lookup", "NVS value read" };

struct settings_timer {
	uint32_t ticks;
	uint32_t measurements;
};

extern uint32_t settings_counter[CNT_MAX];
extern int64_t settings_timer_reference;
extern struct settings_timer settings_timer[TM_MAX];

static inline void settings_counter_inc(enum settings_counter_id cnt)
{
	settings_counter[cnt]++;
}

static inline void settings_timer_start(void)
{
	settings_timer_reference = k_uptime_ticks();
}

static inline void settings_timer_end(enum settings_timer_id tm, bool reset_reference)
{
	int64_t now = k_uptime_ticks();
	settings_timer[tm].measurements++;
	settings_timer[tm].ticks += (uint32_t)(now - settings_timer_reference);

	if (reset_reference) {
		settings_timer_reference = now;
	}
}

#endif
