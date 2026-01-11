/*
 * Helper for loading bundled libraries on macOS
 *
 * On macOS, Wine is often distributed as a self-contained bundle with
 * libraries in a relative path. This header provides a helper function
 * to load libraries from the bundle before falling back to system paths.
 *
 * Copyright 2024 PodoSoju
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_DLOPEN_BUNDLED_H
#define __WINE_DLOPEN_BUNDLED_H

#ifdef __APPLE__

#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/*
 * Load a library from the bundle's lib directory.
 *
 * On macOS, .so files are located in lib/wine/x86_64-unix/ (or i386-unix).
 * Bundled libraries are in lib/. This function constructs the path:
 *   <so_dir>/../../../lib/<libname>
 *
 * Parameters:
 *   libname   - Library filename (e.g., "libfreetype.6.dylib")
 *   func_addr - Address of a function in the calling .so (use current function)
 *
 * Returns:
 *   Handle from dlopen() if successful, NULL otherwise
 */
static inline void *dlopen_bundled(const char *libname, void *func_addr)
{
    Dl_info info;
    char path[PATH_MAX];
    void *handle = NULL;

    if (dladdr(func_addr, &info) && info.dli_fname)
    {
        const char *last_slash = strrchr(info.dli_fname, '/');
        if (last_slash)
        {
            size_t dir_len = last_slash - info.dli_fname;
            /* .so is in lib/wine/{arch}-unix/, bundled libs are in lib/ (3 levels up) */
            snprintf(path, sizeof(path), "%.*s/../../../lib/%s", (int)dir_len, info.dli_fname, libname);
            handle = dlopen(path, RTLD_NOW);
        }
    }
    return handle;
}

/*
 * Macro to try bundled library first, then fall back to system SONAME.
 * Usage:
 *   handle = DLOPEN_BUNDLED_OR_SYSTEM("libfoo.dylib", SONAME_LIBFOO);
 */
#define DLOPEN_BUNDLED_OR_SYSTEM(bundled_name, soname) \
    ({ \
        void *_h = dlopen_bundled(bundled_name, (void *)__builtin_return_address(0)); \
        if (!_h) _h = dlopen(soname, RTLD_NOW); \
        _h; \
    })

/*
 * Override dlopen to automatically try bundled path first.
 * The SONAME typically looks like "libfoo.X.dylib" - we use it directly.
 * Include this header AFTER <dlfcn.h> to override dlopen.
 */
static inline void *dlopen_with_bundled(const char *filename, int flags)
{
    void *handle = NULL;
    if (filename)
    {
        /* Try bundled path first */
        handle = dlopen_bundled(filename, (void *)dlopen_with_bundled);
    }
    if (!handle)
    {
        /* Fall back to original dlopen behavior */
        extern void *__darwin_dlopen(const char *, int);
        handle = __darwin_dlopen(filename, flags);
    }
    return handle;
}

/* Uncomment below to auto-override dlopen (risky - may break things) */
/* #define dlopen(name, flags) dlopen_with_bundled(name, flags) */

#else /* !__APPLE__ */

/* On non-macOS, just use standard dlopen */
#define DLOPEN_BUNDLED_OR_SYSTEM(bundled_name, soname) dlopen(soname, RTLD_NOW)

#endif /* __APPLE__ */

#endif /* __WINE_DLOPEN_BUNDLED_H */
