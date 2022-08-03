/**
Copyright (c) 2013 Simon Zolin
*/

#include <FFOS/time.h>


/** Get system-specific clock value (unrelated to UTC time). */
#if !defined FF_APPLE
static FFINL int ffclk_get(fftime *result) {
	struct timespec ts;
	int r = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (r == 0)
		fftime_fromtimespec(result, &ts);
	else
		fftime_null(result);
	return r;
}
#else
#include <sys/sysctl.h>
static FFINL int ffclk_get(fftime *result) {
	struct timeval tv;
	size_t len = sizeof(tv);
	int mib[] = {CTL_KERN, KERN_BOOTTIME};
	int r = sysctl(mib, 2, &tv, &len, NULL, 0);
	if (r == 0)
		fftime_fromtimeval(result, &tv);
	else
		fftime_null(result);
	return r;
}
#endif

/** Convert the value returned by ffclk_get() to fftime. */
#define ffclk_totime(t)

/** Get clock difference and convert to fftime. */
static FFINL void ffclk_diff(const fftime *start, fftime *stop)
{
	stop->sec -= start->sec;
	stop->nsec -= start->nsec;
	if ((int)stop->nsec < 0) {
		stop->nsec += 1000000000;
		stop->sec--;
	}
}
