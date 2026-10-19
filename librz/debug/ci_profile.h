// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only
//
// Private, opt-in CI instrumentation. Do not expose this header as public API.
// Enable with RZ_DEBUG_PROFILE_DIR=/absolute/writable/path.
// Each library translation unit dumps one small per-PID JSON file at exit.
#ifndef RZ_CI_DEBUG_PROFILE_H
#define RZ_CI_DEBUG_PROFILE_H

#include <rz_util/rz_sys.h>
#include <rz_util/rz_time.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef RZ_CI_PROFILE_UNIT
#error "Define RZ_CI_PROFILE_UNIT before including this internal header"
#endif
#ifndef RZ_CI_PROFILE_NAMES
#error "Define RZ_CI_PROFILE_NAMES before including this internal header"
#endif

enum { RZ_CI_PROFILE_BUCKETS = 3 };
static const char *const rz_ci_profile_names[RZ_CI_PROFILE_BUCKETS] = RZ_CI_PROFILE_NAMES;
static ut64 rz_ci_profile_calls[RZ_CI_PROFILE_BUCKETS];
static ut64 rz_ci_profile_us[RZ_CI_PROFILE_BUCKETS];

static void rz_ci_profile_dump(void) {
	const char *directory = getenv("RZ_DEBUG_PROFILE_DIR");
	if (!directory || !*directory) {
		return;
	}
	char path[4096];
	int n = snprintf(path, sizeof(path), "%s/rizin-%s-%d.json",
		directory, RZ_CI_PROFILE_UNIT, rz_sys_getpid());
	if (n < 0 || (size_t)n >= sizeof(path)) {
		return;
	}
	FILE *out = fopen(path, "w");
	if (!out) {
		return;
	}
	fprintf(out, "{\"schema\":1,\"unit\":\"%s\",\"pid\":%d,\"metrics\":[",
		RZ_CI_PROFILE_UNIT, rz_sys_getpid());
	for (int i = 0; i < RZ_CI_PROFILE_BUCKETS; i++) {
		fprintf(out, "%s{\"name\":\"%s\",\"calls\":%llu,\"total_us\":%llu}",
			i ? "," : "", rz_ci_profile_names[i],
			(unsigned long long)rz_ci_profile_calls[i],
			(unsigned long long)rz_ci_profile_us[i]);
	}
	fputs("]}\n", out);
	fclose(out);
}

static inline bool rz_ci_profile_enabled(void) {
	static int state = -1;
	if (state == -1) {
		const char *dir = getenv("RZ_DEBUG_PROFILE_DIR");
		state = dir && *dir && atexit(rz_ci_profile_dump) == 0 ? 1 : 0;
	}
	return state == 1;
}

static inline ut64 rz_ci_profile_start(void) {
	return rz_ci_profile_enabled() ? rz_time_now_mono() : 0;
}

static inline void rz_ci_profile_end(int bucket, ut64 start) {
	if (start && bucket >= 0 && bucket < RZ_CI_PROFILE_BUCKETS) {
		ut64 end = rz_time_now_mono();
		rz_ci_profile_calls[bucket]++;
		if (end >= start) {
			rz_ci_profile_us[bucket] += end - start;
		}
	}
}

static inline void rz_ci_profile_count(int bucket) {
	if (rz_ci_profile_enabled() && bucket >= 0 && bucket < RZ_CI_PROFILE_BUCKETS) {
		rz_ci_profile_calls[bucket]++;
	}
}

#endif // RZ_CI_DEBUG_PROFILE_H
