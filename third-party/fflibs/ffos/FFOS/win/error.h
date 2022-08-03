/**
Copyright (c) 2013 Simon Zolin
*/

#include <FFOS/string.h>


#define fferr_last  GetLastError

#define fferr_set  SetLastError

FF_EXTN int fferr_strq(int code, ffsyschar *dst, size_t dst_cap);

static FFINL int fferr_str(int code, char *dst, size_t dst_cap)
{
	ffsyschar w[255];
	fferr_strq(code, w, FFCNT(w));
	if (0 == ff_wtou(dst, dst_cap, w, -1, 0)) {
		if (dst_cap != 0)
			dst[0] = '\0';
		return -1;
	}
	return 0;
}

FF_EXTN const char* fferr_strp(int code);

#define fferr_again(code)  (code == WSAEWOULDBLOCK)

#define fferr_exist(code)  ((code) == ERROR_FILE_EXISTS || (code) == ERROR_ALREADY_EXISTS)

#define fferr_fdlim(code)  (0)

/**
return 0 if b = TRUE or (b = FALSE and IO_PENDING)
return -1 if b = FALSE and !IO_PENDING */
#define fferr_ioret(b) (((b) || GetLastError() == ERROR_IO_PENDING) ? 0 : -1)

static FFINL ffbool fferr_nofile(int e) {
	return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND
		|| e == ERROR_NOT_READY || e == ERROR_INVALID_NAME;
}


// we can't use names without "FF_" prefix here because it would conflict with include files from mingw
enum FF_ERRORS {
	FF_EINVAL = ERROR_INVALID_PARAMETER
	, FF_EEXIST = ERROR_ALREADY_EXISTS //ERROR_FILE_EXISTS
	, FF_EOVERFLOW = ERROR_INVALID_DATA
	, FF_ENOSPC = ERROR_DISK_FULL
	, FF_EBADF = ERROR_INVALID_HANDLE
	, FF_ENOMEM = ERROR_NOT_ENOUGH_MEMORY
	, FF_EACCES = ERROR_ACCESS_DENIED
	, FF_ENOTEMPTY = ERROR_DIR_NOT_EMPTY
	, FF_ETIMEDOUT = WSAETIMEDOUT
	, FF_EAGAIN = WSAEWOULDBLOCK
	, FF_ECANCELED = ERROR_OPERATION_ABORTED
	, FF_EINTR = WAIT_TIMEOUT
	,
	FF_ENOENT = ERROR_FILE_NOT_FOUND,
	FF_ENOSYS = ERROR_NOT_SUPPORTED,
};
