// SPDX-FileCopyrightText: 2026 Rizin CI contributors
// SPDX-License-Identifier: LGPL-3.0-only
//
// Optional, Linux-only CI timing. No files, logs, or timers are used unless
// RZ_CI_DEBUG_PROFILE_PATH is explicitly set by the dedicated debugger job.
#ifndef RZ_CI_DEBUG_PROFILE_H
#define RZ_CI_DEBUG_PROFILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#if defined(__linux__)
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#endif

typedef struct {
	const char *label;
	unsigned long long calls;
	unsigned long long total_ns;
	unsigned long long max_ns;
} RzCiDebugProfileBucket;

typedef struct {
	int enabled; // -1 = not initialized, 0 = off, 1 = on
	const char *source;
	RzCiDebugProfileBucket *buckets;
	size_t count;
} RzCiDebugProfile;

static inline uint64_t rz_ci_debug_profile_start(RzCiDebugProfile *p, void (*dump_at_exit)(void)) {
#if defined(__linux__)
	if (p->enabled == -1) {
		const char *path = getenv("RZ_CI_DEBUG_PROFILE_PATH");
		p->enabled = (path && *path) ? 1 : 0;
		if (p->enabled) {
			atexit(dump_at_exit);
		}
	}
	if (p->enabled) {
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
		}
	}
#else
	(void)p;
	(void)dump_at_exit;
#endif
	return 0;
}

static inline void rz_ci_debug_profile_end(RzCiDebugProfile *p, size_t bucket, uint64_t start) {
#if defined(__linux__)
	if (!start || bucket >= p->count) {
		return;
	}
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		return;
	}
	uint64_t end = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
	if (end < start) {
		return;
	}
	unsigned long long elapsed = (unsigned long long)(end - start);
	RzCiDebugProfileBucket *b = &p->buckets[bucket];
	__atomic_fetch_add(&b->calls, 1ULL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&b->total_ns, elapsed, __ATOMIC_RELAXED);
	unsigned long long prior = __atomic_load_n(&b->max_ns, __ATOMIC_RELAXED);
	while (prior < elapsed && !__atomic_compare_exchange_n(&b->max_ns, &prior, elapsed,
			false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		// Repeat if another thread increased the maximum.
	}
#else
	(void)p;
	(void)bucket;
	(void)start;
#endif
}

static inline void rz_ci_debug_profile_dump(RzCiDebugProfile *p) {
#if defined(__linux__)
	if (p->enabled != 1) {
		return;
	}
	const char *path = getenv("RZ_CI_DEBUG_PROFILE_PATH");
	if (!path || !*path) {
		return;
	}
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		return;
	}
	for (size_t i = 0; i < p->count; i++) {
		const RzCiDebugProfileBucket *b = &p->buckets[i];
		if (!b->calls) {
			continue;
		}
		char line[300];
		int n = snprintf(line, sizeof(line),
			"{\"schema\":1,\"pid\":%lld,\"source\":\"%s\",\"stage\":\"%s\",\"calls\":%llu,\"total_ns\":%llu,\"max_ns\":%llu}\n",
			(long long)getpid(), p->source, b->label,
			__atomic_load_n(&b->calls, __ATOMIC_RELAXED),
			__atomic_load_n(&b->total_ns, __ATOMIC_RELAXED),
			__atomic_load_n(&b->max_ns, __ATOMIC_RELAXED));
		if (n > 0 && (size_t)n < sizeof(line)) {
			(void)write(fd, line, (size_t)n);
		}
	}
	close(fd);
#else
	(void)p;
#endif
}

#endif // RZ_CI_DEBUG_PROFILE_H
