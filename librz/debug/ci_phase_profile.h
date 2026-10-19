// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only
//
// Experimental opt-in CI profiler. Include only in the debug implementation
// files that need phase accounting. Zero clock calls and no output by default.
#ifndef RZ_DEBUG_CI_PHASE_PROFILE_H
#define RZ_DEBUG_CI_PHASE_PROFILE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RZ_CI_PROFILE_MODULE
#error "Define RZ_CI_PROFILE_MODULE before including ci_phase_profile.h"
#endif

#define RZ_CI_PROFILE_MAX_PHASES 12

typedef struct {
	const char *name;
	unsigned long long calls;
	uint64_t total_ns;
	uint64_t max_ns;
	unsigned long long events;
} RzCiPhaseEntry;

static RzCiPhaseEntry rz_ci_phase_entries[RZ_CI_PROFILE_MAX_PHASES];
static int rz_ci_phase_enabled = -1;

#if defined(__linux__)
#include <unistd.h>
#endif

static void rz_ci_phase_report(void) {
	FILE *output = stderr;
#if defined(__linux__)
	const char *dir = getenv("RZ_CI_DEBUG_PROFILE_DIR");
	if (dir && *dir) {
		char path[4096];
		int length = snprintf(path, sizeof(path), "%s/rizin-%ld-%s.txt",
			dir, (long)getpid(), RZ_CI_PROFILE_MODULE);
		if (length > 0 && (size_t)length < sizeof(path)) {
			FILE *profile_file = fopen(path, "w");
			if (profile_file) {
				output = profile_file;
			}
		}
	}
#endif
	for (size_t i = 0; i < RZ_CI_PROFILE_MAX_PHASES; ++i) {
		RzCiPhaseEntry *entry = &rz_ci_phase_entries[i];
		if (!entry->name) {
			continue;
		}
		fprintf(output,
			"RZ_CI_PROFILE module=%s phase=%s calls=%llu total_us=%llu max_us=%llu events=%llu\n",
			RZ_CI_PROFILE_MODULE, entry->name, entry->calls,
			(unsigned long long)(entry->total_ns / 1000),
			(unsigned long long)(entry->max_ns / 1000), entry->events);
	}
	if (output != stderr) {
		fclose(output);
	}
}

static int rz_ci_phase_is_enabled(void) {
	if (rz_ci_phase_enabled == -1) {
		const char *opt = getenv("RZ_CI_DEBUG_PROFILE");
		rz_ci_phase_enabled = opt && !strcmp(opt, "1");
		if (rz_ci_phase_enabled) {
			atexit(rz_ci_phase_report);
		}
	}
	return rz_ci_phase_enabled;
}

#if defined(__linux__)
#include <time.h>

static inline uint64_t rz_ci_phase_now(void) {
	struct timespec clock_value;
	if (clock_gettime(CLOCK_MONOTONIC, &clock_value)) {
		return 0;
	}
	return ((uint64_t)clock_value.tv_sec * 1000000000ULL) +
		(uint64_t)clock_value.tv_nsec;
}

static inline uint64_t rz_ci_phase_begin(void) {
	return rz_ci_phase_is_enabled() ? rz_ci_phase_now() : 0;
}

static inline void rz_ci_phase_end(unsigned slot, const char *name, uint64_t begin_ns) {
	if (!begin_ns || slot >= RZ_CI_PROFILE_MAX_PHASES) {
		return;
	}
	uint64_t end_ns = rz_ci_phase_now();
	uint64_t elapsed = end_ns >= begin_ns ? end_ns - begin_ns : 0;
	RzCiPhaseEntry *entry = &rz_ci_phase_entries[slot];
	entry->name = name;
	entry->calls++;
	entry->total_ns += elapsed;
	if (elapsed > entry->max_ns) {
		entry->max_ns = elapsed;
	}
}

static inline void rz_ci_phase_count(unsigned slot, const char *name, unsigned long long amount) {
	if (!rz_ci_phase_is_enabled() || slot >= RZ_CI_PROFILE_MAX_PHASES) {
		return;
	}
	RzCiPhaseEntry *entry = &rz_ci_phase_entries[slot];
	entry->name = name;
	entry->events += amount;
}

#else

static inline uint64_t rz_ci_phase_begin(void) {
	return 0;
}

static inline void rz_ci_phase_end(unsigned slot, const char *name, uint64_t begin_ns) {
	(void)slot;
	(void)name;
	(void)begin_ns;
}

static inline void rz_ci_phase_count(unsigned slot, const char *name, unsigned long long amount) {
	(void)slot;
	(void)name;
	(void)amount;
}

#endif
#endif
