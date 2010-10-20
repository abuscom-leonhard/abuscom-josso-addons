/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/***************************************************************************
 * Description: Memory Pool object header file                             *
 * Author:      Gal Shachor <shachor@il.ibm.com>                           *
 * Version:     $Revision: 466585 $                                           *
 ***************************************************************************/
#ifndef _JK_POOL_H
#define _JK_POOL_H

#include "jk_global.h"

#ifdef __cplusplus
extern "C"
{
#endif                          /* __cplusplus */

/**
 * @file jk_pool.h
 * @brief Jk memory allocation
 *
 * Similar with apr_pools, but completely unsynchronized.
 * XXX use same names
 * 
 */

/*
 * The pool atom (basic pool alocation unit) is an 8 byte long. 
 * Each allocation (even for 1 byte) will return a round up to the 
 * number of atoms. 
 * 
 * This is to help in alignment of 32/64 bit machines ...
 * G.S
 */
#ifdef WIN32
    typedef __int64 jk_pool_atom_t;
#elif defined(AIX)
    typedef long long jk_pool_atom_t;
#elif defined(SOLARIS)
    typedef long long jk_pool_atom_t;
#elif defined(LINUX)
    typedef long long jk_pool_atom_t;
#elif defined(FREEBSD)
    typedef long long jk_pool_atom_t;
#elif defined(OS2)
    typedef long long jk_pool_atom_t;
#elif defined(NETWARE)
    typedef long long jk_pool_atom_t;
#elif defined(HPUX11)
    typedef long long jk_pool_atom_t;
#elif defined(IRIX)
    typedef long long jk_pool_atom_t;
#elif defined(AS400)
    typedef void *jk_pool_atom_t;
#else
    typedef long long jk_pool_atom_t;
#endif

/**
 * Alignment macros
 */

/* JK_ALIGN() is only to be used to align on a power of 2 boundary */
#define JK_ALIGN(size, boundary) \
    (((size) + ((boundary) - 1)) & ~((boundary) - 1))

/** Default alignment */
#ifdef AS400
#define JK_ALIGN_DEFAULT(size) JK_ALIGN(size, 16)
#else
#define JK_ALIGN_DEFAULT(size) JK_ALIGN(size, 8)
#endif

/* 
 * Pool size in number of pool atoms.
 */
#define TINY_POOL_SIZE 256      /* Tiny 1/4K atom pool. */
#define SMALL_POOL_SIZE 512     /* Small 1/2K atom pool. */
#define BIG_POOL_SIZE   2*SMALL_POOL_SIZE       /* Bigger 1K atom pool. */
#define HUGE_POOL_SIZE  2*BIG_POOL_SIZE /* Huge 2K atom pool. */

/** jk pool structure */
struct jk_pool
{
    size_t size;
    size_t pos;
    char *buf;
    size_t dyn_size;
    size_t dyn_pos;
    void **dynamic;
};

typedef struct jk_pool jk_pool_t;

void jk_open_pool(jk_pool_t *p, jk_pool_atom_t *buf, size_t size);

void jk_close_pool(jk_pool_t *p);

void jk_reset_pool(jk_pool_t *p);

void *jk_pool_alloc(jk_pool_t *p, size_t sz);

void *jk_pool_realloc(jk_pool_t *p,
                      size_t sz, const void *old, size_t old_sz);

void *jk_pool_strdup(jk_pool_t *p, const char *s);

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* _JK_POOL_H */
