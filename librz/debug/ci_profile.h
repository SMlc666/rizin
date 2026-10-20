// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only
//
// Experimental, opt-in, per-process CI timing. Not a public API.
// Set RZ_DEBUG_CI_PROFILE_LOG to an absolute path on archos-heavy only.
// Each translation unit supplies RZ_CI_PROFILE_UNIT and
// RZ_CI_PROFILE_PHASE_NAMES before including this header.
#ifndef RZ_DEBUG_CI_PROFILE_H
#define RZ_DEBUG_CI_PROFILE_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <rz_util/rz_time.h>

static const char *const rz_ci_profile_phase_names[] = RZ_CI_PROFILE_PHASE_NAMES;
static struct {
	uint64_t calls;
	uint64_t elapsed_us;
} rz_ci_profile_data[sizeof(rz_ci_profile_phase_names) / sizeof(rz_ci_profile_phase_names[0])];
static const char *rz_ci_profile_log_path;
static int rz_ci_profile_active = -1;

static void rz_ci_profile_dump(void) {
	if (!rz_ci_profile_log_path) {
		return;
	}
	FILE *out = fopen(rz_ci_profile_log_path, "a");
	if (!out) {
		fprintf(stderr, "RZCI_PROFILE: could not append timing report\n");
		return;
	}
	for (size_t i = 0; i < sizeof(rz_ci_profile_data) / sizeof(rz_ci_profile_data[0]); i++) {
		if (rz_ci_profile_data[i].calls) {
			fprintf(out, "RZCI_PROFILE\tunit=%s\tphase=%s\tcalls=%" PRIu64 "\tus=%" PRIu64 "\n",
				RZ_CI_PROFILE_UNIT, rz_ci_profile_phase_names[i],
				rz_ci_profile_data[i].calls, rz_ci_profile_data[i].elapsed_us);
		}
	}
	fclose(out);
}

static inline bool rz_ci_profile_enabled(void) {
	if (rz_ci_profile_active < 0) {
		const char *path = getenv("RZ_DEBUG_CI_PROFILE_LOG");
		rz_ci_profile_active = (path && *path) ? 1 : 0;
		if (rz_ci_profile_active) {
			rz_ci_profile_log_path = path;
			atexit(rz_ci_profile_dump);
		}
	}
	return rz_ci_profile_active == 1;
}

static inline ut64 rz_ci_profile_begin(void) {
	return rz_ci_profile_enabled() ? rz_time_now_mono() : 0;
}

static inline void rz_ci_profile_end(size_t phase, ut64 start_us) {
	if (start_us) {
		const ut64 now_us = rz_time_now_mono();
		rz_ci_profile_data[phase].calls++;
		if (now_us >= start_us) {
			rz_ci_profile_data[phase].elapsed_us += now_us - start_us;
		}
	}
}

static inline void rz_ci_profile_count(size_t phase, ut64 events) {
	if (rz_ci_profile_enabled()) {
		rz_ci_profile_data[phase].calls += events;
	}
}

#endif // RZ_DEBUG_CI_PROFILE_H
