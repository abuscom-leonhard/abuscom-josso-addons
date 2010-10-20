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
 * Description: Simple memory pool                                         *
 * Author:      Gal Shachor <shachor@il.ibm.com>                           *
 * Version:     $Revision: 466585 $                                           *
 ***************************************************************************/

#include "jk_pool.h"

#define DEFAULT_DYNAMIC 10


static void *jk_pool_dyn_alloc(jk_pool_t *p, size_t size);


void jk_open_pool(jk_pool_t *p, jk_pool_atom_t *buf, size_t size)
{
    p->pos = 0;
    p->size = size;
    p->buf = (char *)buf;

    p->dyn_pos = 0;
    p->dynamic = NULL;
    p->dyn_size = 0;
}

void jk_close_pool(jk_pool_t *p)
{
    jk_reset_pool(p);
    if (p->dynamic) {
        free(p->dynamic);
    }
}

void jk_reset_pool(jk_pool_t *p)
{
    if (p->dyn_pos && p->dynamic) {
        size_t i;
        for (i = 0; i < p->dyn_pos; i++) {
            if (p->dynamic[i]) {
                free(p->dynamic[i]);
            }
        }
    }

    p->dyn_pos = 0;
    p->pos = 0;
}

void *jk_pool_alloc(jk_pool_t *p, size_t size)
{
    void *rc = NULL;

    size = JK_ALIGN_DEFAULT(size);
    if ((p->size - p->pos) >= size) {
        rc = &(p->buf[p->pos]);
        p->pos += size;
    }
    else {
        rc = jk_pool_dyn_alloc(p, size);
    }

    return rc;
}

void *jk_pool_realloc(jk_pool_t *p, size_t sz, const void *old, size_t old_sz)
{
    void *rc;

    if (!p || (!old && old_sz)) {
        return NULL;
    }

    rc = jk_pool_alloc(p, sz);
    if (rc) {
        memcpy(rc, old, old_sz);
    }

    return rc;
}

void *jk_pool_strdup(jk_pool_t *p, const char *s)
{
    void *rc = NULL;
    if (s && p) {
        size_t size = strlen(s);

        if (!size) {
            return "";
        }

        size++;
        rc = jk_pool_alloc(p, size);
        if (rc) {
            memcpy(rc, s, size);
        }
    }

    return rc;
}

#if defined (DEBUG) || defined(_DEBUG)
static void jk_dump_pool(jk_pool_t *p, FILE * f)
{
    fprintf(f, "Dumping for pool [%p]\n",  p);
    fprintf(f, "size             [%ld]\n", p->size);
    fprintf(f, "pos              [%ld]\n", p->pos);
    fprintf(f, "buf              [%p]\n",  p->buf);
    fprintf(f, "dyn_size         [%ld]\n", p->dyn_size);
    fprintf(f, "dyn_pos          [%ld]\n", p->dyn_pos);
    fprintf(f, "dynamic          [%p]\n",  p->dynamic);

    fflush(f);
}
#endif

static void *jk_pool_dyn_alloc(jk_pool_t *p, size_t size)
{
    void *rc;

    if (p->dyn_size == p->dyn_pos) {
        size_t new_dyn_size = p->dyn_size * 2 + DEFAULT_DYNAMIC;
        void **new_dynamic = (void **)malloc(new_dyn_size * sizeof(void *));
        if (new_dynamic) {
            if (p->dynamic) {
                /* Copy old dynamic slots */
                memcpy(new_dynamic, p->dynamic, p->dyn_size * sizeof(void *));

                free(p->dynamic);
            }

            p->dynamic = new_dynamic;
            p->dyn_size = new_dyn_size;
        }
        else {
#if defined (DEBUG) || defined(_DEBUG)
            jk_dump_pool(p, stderr);
#endif            
            return NULL;
        }
    }

    rc = p->dynamic[p->dyn_pos] = malloc(size);
    if (p->dynamic[p->dyn_pos]) {
        p->dyn_pos++;
    }

    return rc;
}
