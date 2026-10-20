// SPDX-FileCopyrightText: 2026 Rizin CI instrumentation contributors
// SPDX-License-Identifier: LGPL-3.0-only
//
// EXPERIMENTAL: Linux x86_64-only, opt-in CI profiling. Does not modify
// debugger logic or test expected output; emits one CSV per process/module at
// normal process exit. This header intentionally has translation-unit-local
// counters, so no new public symbols or ABI changes are introduced.
//
// Define RZ_CI_PROFILE_MODULE and RZ_CI_PROFILE_BUCKETS before including.
#ifndef RZ_CI_DEBUG_PROFILE_H
#define RZ_CI_DEBUG_PROFILE_H

#include <rz_util/rz_time.h>

#if defined(__linux__) && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
	const char *phase;
	unsigned long long calls;
	unsigned long long total_us;
} RzCiProfileBucket;

static RzCiProfileBucket rz_ci_profile_buckets[] = { RZ_CI_PROFILE_BUCKETS };
static int rz_ci_profile_state = 0; // 0 unknown; -1 initializing; 1 disabled; 2 enabled
static char rz_ci_profile_prefix[2048];

static void rz_ci_profile_flush(void) {
	char filename[2304];
	int n = snprintf(filename, sizeof(filename), "%s.%ld.%s.csv",
		rz_ci_profile_prefix, (long)getpid(), RZ_CI_PROFILE_MODULE);
	if (n < 0 || (size_t)n >= sizeof(filename)) {
		return;
	}
	FILE *out = fopen(filename, "w");
	if (!out) {
		return;
	}
	fprintf(out, "module,phase,calls,total_us\n");
	for (size_t i = 0; i < sizeof(rz_ci_profile_buckets) / sizeof(rz_ci_profile_buckets[0]); i++) {
		const RzCiProfileBucket *b = &rz_ci_profile_buckets[i];
		fprintf(out, "%s,%s,%llu,%llu\n",
			RZ_CI_PROFILE_MODULE, b->phase,
			__atomic_load_n(&b->calls, __ATOMIC_RELAXED),
			__atomic_load_n(&b->total_us, __ATOMIC_RELAXED));
	}
	fclose(out);
}

static inline bool rz_ci_profile_enabled(void) {
	int state = __atomic_load_n(&rz_ci_profile_state, __ATOMIC_ACQUIRE);
	if (state == 0) {
		int expected = 0;
		if (__atomic_compare_exchange_n(&rz_ci_profile_state, &expected, -1,
				false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			const char *prefix = getenv("RZ_CI_DEBUG_PROFILE_PATH");
			int enabled = prefix && *prefix && strlen(prefix) < sizeof(rz_ci_profile_prefix);
			if (enabled) {
				memcpy(rz_ci_profile_prefix, prefix, strlen(prefix) + 1);
				atexit(rz_ci_profile_flush);
			}
			__atomic_store_n(&rz_ci_profile_state, enabled ? 2 : 1, __ATOMIC_RELEASE);
			return enabled;
		}
		state = expected;
	}
	while (state == -1) {
		state = __atomic_load_n(&rz_ci_profile_state, __ATOMIC_ACQUIRE);
	}
	return state == 2;
}

static inline ut64 rz_ci_profile_begin(void) {
	return rz_ci_profile_enabled() ? rz_time_now_mono() : 0;
}

static inline void rz_ci_profile_end(size_t index, ut64 start) {
	if (!start || index >= sizeof(rz_ci_profile_buckets) / sizeof(rz_ci_profile_buckets[0])) {
		return;
	}
	ut64 now = rz_time_now_mono();
	if (now >= start) {
		__atomic_fetch_add(&rz_ci_profile_buckets[index].calls, 1ULL, __ATOMIC_RELAXED);
		__atomic_fetch_add(&rz_ci_profile_buckets[index].total_us,
			(unsigned long long)(now - start), __ATOMIC_RELAXED);
	}
}
#else
// Other systems compile the same debugger behavior, with profiling disabled.
static inline ut64 rz_ci_profile_begin(void) { return 0; }
static inline void rz_ci_profile_end(size_t index, ut64 start) {
	(void)index;
	(void)start;
}
#endif
#endif // RZ_CI_DEBUG_PROFILE_H
