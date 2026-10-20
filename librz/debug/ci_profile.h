// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only
// Opt-in CI instrumentation: no addresses, payloads or process arguments logged.
#ifndef RZ_DEBUG_CI_PROFILE_H
#define RZ_DEBUG_CI_PROFILE_H
#include <rz_util/rz_time.h>
#include <rz_util/rz_sys.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef RZ_CI_PROFILE_MODULE
#error "RZ_CI_PROFILE_MODULE must be defined"
#endif
typedef struct {
	const char *name;
	ut64 calls;
	ut64 total_us;
} RzCiProfileMetric;
static RzCiProfileMetric rz_ci_metrics[12];
static int rz_ci_profile_active = -1;
static const char *rz_ci_profile_dir;
static void rz_ci_profile_flush(void) {
	if (!rz_ci_profile_dir) return;
	char path[4096];
	int n = snprintf(path, sizeof(path), "%s/rizin-%s-%d.tsv",
		rz_ci_profile_dir, RZ_CI_PROFILE_MODULE, rz_sys_getpid());
	if (n < 0 || (size_t)n >= sizeof(path)) return;
	FILE *f = fopen(path, "w");
	if (!f) return;
	for (size_t i = 0; i < 12; i++) {
		RzCiProfileMetric *m = &rz_ci_metrics[i];
		if (m->name && m->calls) {
			fprintf(f, "v1\t%s\t%s\t%llu\t%llu\n",
				RZ_CI_PROFILE_MODULE, m->name,
				(unsigned long long)m->calls,
				(unsigned long long)m->total_us);
		}
	}
	fclose(f);
}
static inline bool rz_ci_profile_enabled(void) {
	if (rz_ci_profile_active == -1) {
		rz_ci_profile_dir = getenv("RZ_DEBUG_CI_PROFILE_DIR");
		rz_ci_profile_active = rz_ci_profile_dir && *rz_ci_profile_dir ? 1 : 0;
		if (rz_ci_profile_active) atexit(rz_ci_profile_flush);
	}
	return rz_ci_profile_active == 1;
}
static inline ut64 rz_ci_profile_start(void) {
	return rz_ci_profile_enabled() ? rz_time_now_mono() : 0;
}
static inline void rz_ci_profile_end(size_t idx, const char *name, ut64 start) {
	if (!start || idx >= 12) return;
	RzCiProfileMetric *m = &rz_ci_metrics[idx];
	m->name = name;
	m->calls++;
	m->total_us += rz_time_now_mono() - start;
}
static inline void rz_ci_profile_count(size_t idx, const char *name) {
	if (!rz_ci_profile_enabled() || idx >= 12) return;
	RzCiProfileMetric *m = &rz_ci_metrics[idx];
	m->name = name;
	m->calls++;
}
#endif
