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
 * Description: Utility functions (mainly configuration)                   *
 * Author:      Gal Shachor <shachor@il.ibm.com>                           *
 * Author:      Henri Gomez <hgomez@apache.org>                            *
 * Author:      Rainer Jung <rjung@apache.org>                             *
 * Version:     $Revision: 704015 $                                          *
 ***************************************************************************/


#include "jk_util.h"
#include "jk_mt.h"


#define HUGE_BUFFER_SIZE (8*1024)

/*
 * define the log format, we're using by default the one from error.log
 *
 * [Mon Mar 26 19:44:48.123 2001] [jk_uri_worker_map.c (155)]: Into jk_uri_worker_map_t::uri_worker_map_alloc
 * log format used by apache in error.log
 */
#define JK_TIME_CONV_MILLI    "%Q"
#define JK_TIME_CONV_MICRO    "%q"
#define JK_TIME_PATTERN_MILLI "000"
#define JK_TIME_PATTERN_MICRO "000000"
#define JK_TIME_FORMAT_NONE   "[%a %b %d %H:%M:%S %Y] "
#define JK_TIME_FORMAT_MILLI  "[%a %b %d %H:%M:%S." JK_TIME_CONV_MILLI " %Y] "
#define JK_TIME_FORMAT_MICRO  "[%a %b %d %H:%M:%S." JK_TIME_CONV_MICRO " %Y] "
#define JK_TIME_SUBSEC_NONE   (0)
#define JK_TIME_SUBSEC_MILLI  (1)
#define JK_TIME_SUBSEC_MICRO  (2)

#define DEFAULT_LB_FACTOR           (1)
#define DEFAULT_DISTANCE            (0)


/* Visual C++ Toolkit 2003 support */
#if defined (_MSC_VER) && (_MSC_VER == 1310)
    extern long _ftol(double); /* defined by VC6 C libs */
    extern long _ftol2(double dblSource) { return _ftol(dblSource); }
#endif

static const char *jk_level_verbs[] = {
    "[" JK_LOG_TRACE_VERB "] ",
    "[" JK_LOG_DEBUG_VERB "] ",
    "[" JK_LOG_INFO_VERB "] ",
    "[" JK_LOG_WARN_VERB "] ",
    "[" JK_LOG_ERROR_VERB "] ",
    "[" JK_LOG_EMERG_VERB "] ",
    NULL
};

const char *jk_get_bool(int v)
{
    if (v == 0)
        return "False";
    else
        return "True";
}

int jk_get_bool_code(const char *v, int def)
{
    if (!v) {
        return def;
    }
    else if (!strcasecmp(v, "off") ||
             *v == 'F' || *v == 'f' ||
             *v == 'N' || *v == 'n' ||
            (*v == '0' && *(v + 1) == '\0')) {
        return 0;
    }
    else if (!strcasecmp(v, "on") ||
             *v == 'T' || *v == 't' ||
             *v == 'Y' || *v == 'y' ||
            (*v == '1' && *(v + 1) == '\0')) {
        return 1;
    }
    return def;
}

/* Sleep for 100ms */
void jk_sleep(int ms)
{
#ifdef OS2
    DosSleep(ms);
#elif defined(BEOS)
    snooze(ms * 1000);
#elif defined(NETWARE)
    delay(ms);
#elif defined(WIN32)
    Sleep(ms);
#else
    struct timeval tv;
    tv.tv_usec = (ms % 1000) * 1000;
    tv.tv_sec = ms / 1000;
    select(0, NULL, NULL, NULL, &tv);
#endif
}

/* Replace the first occurence of a sub second time format character
 * by a series of zero digits with the right precision.
 * We format our timestamp with strftime, but this can not handle
 * sub second timestamps.
 * So we first patch the milliseconds or microseconds literally into
 * the format string, and then pass it on the strftime.
 * In order to do that efficiently, we prepare a format string, that
 * already has placeholder digits for the sub second time stamp
 * and we save the position and time precision of this placeholder.
 */
void jk_set_time_fmt(jk_logger_t *l, const char *jk_log_fmt)
{
    if (l) {
        char *s;

        if (!jk_log_fmt) {
#ifndef NO_GETTIMEOFDAY
            jk_log_fmt = JK_TIME_FORMAT_MILLI;
#else
            jk_log_fmt = JK_TIME_FORMAT_NONE;
#endif
        }
        l->log_fmt_type = JK_TIME_SUBSEC_NONE;
        l->log_fmt_offset = 0;
        l->log_fmt_size = 0;
        l->log_fmt = jk_log_fmt;

/* Look for the first occurence of JK_TIME_CONV_MILLI */
        if ((s = strstr(jk_log_fmt, JK_TIME_CONV_MILLI))) {
            size_t offset = s - jk_log_fmt;
            size_t len = strlen(JK_TIME_PATTERN_MILLI);

/* If we don't have enough space in our fixed-length char array,
 * we simply stick to the default format, ignoring JK_TIME_CONV_MILLI.
 * Otherwise we replace the first occurence of JK_TIME_CONV_MILLI by JK_TIME_PATTERN_MILLI.
 */
            if (offset + len < JK_TIME_MAX_SIZE) {
                l->log_fmt_type = JK_TIME_SUBSEC_MILLI;
                l->log_fmt_offset = offset;
                strncpy(l->log_fmt_subsec, jk_log_fmt, offset);
                strncpy(l->log_fmt_subsec + offset, JK_TIME_PATTERN_MILLI, len);
                strncpy(l->log_fmt_subsec + offset + len,
                        s + strlen(JK_TIME_CONV_MILLI),
                        JK_TIME_MAX_SIZE - offset - len - 1);
/* Now we put a stop mark into the string to make it's length at most JK_TIME_MAX_SIZE-1
 * plus terminating '\0'.
 */
                l->log_fmt_subsec[JK_TIME_MAX_SIZE-1] = '\0';
                l->log_fmt_size = strlen(l->log_fmt_subsec);
            }
/* Look for the first occurence of JK_TIME_CONV_MICRO */
        }
        else if ((s = strstr(jk_log_fmt, JK_TIME_CONV_MICRO))) {
            size_t offset = s - jk_log_fmt;
            size_t len = strlen(JK_TIME_PATTERN_MICRO);

/* If we don't have enough space in our fixed-length char array,
 * we simply stick to the default format, ignoring JK_TIME_CONV_MICRO.
 * Otherwise we replace the first occurence of JK_TIME_CONV_MICRO by JK_TIME_PATTERN_MICRO.
 */
            if (offset + len < JK_TIME_MAX_SIZE) {
                l->log_fmt_type = JK_TIME_SUBSEC_MICRO;
                l->log_fmt_offset = offset;
                strncpy(l->log_fmt_subsec, jk_log_fmt, offset);
                strncpy(l->log_fmt_subsec + offset, JK_TIME_PATTERN_MICRO, len);
                strncpy(l->log_fmt_subsec + offset + len,
                        s + strlen(JK_TIME_CONV_MICRO),
                        JK_TIME_MAX_SIZE - offset - len - 1);
/* Now we put a stop mark into the string to make it's length at most JK_TIME_MAX_SIZE-1
 * plus terminating '\0'.
 */
                l->log_fmt_subsec[JK_TIME_MAX_SIZE-1] = '\0';
                l->log_fmt_size = strlen(l->log_fmt_subsec);
            }
        }
        jk_log(l, JK_LOG_DEBUG, "Pre-processed log time stamp format is '%s'",
               l->log_fmt_type == JK_TIME_SUBSEC_NONE ? l->log_fmt : l->log_fmt_subsec);
    }
}

static int set_time_str(char *str, int len, jk_logger_t *l)
{
    time_t t;
    struct tm *tms;
#ifdef _MT_CODE_PTHREAD
    struct tm res;
#endif
    int done;
/* We want to use a fixed maximum size buffer here.
 * If we would dynamically adjust it to the real format
 * string length, we could support longer format strings,
 * but we would have to allocate and free for each log line.
 */
    char log_fmt[JK_TIME_MAX_SIZE];

    if (!l || !l->log_fmt) {
        return 0;
    }

    log_fmt[0] = '\0';

#ifndef NO_GETTIMEOFDAY
    if ( l->log_fmt_type != JK_TIME_SUBSEC_NONE ) {
        struct timeval tv;
        int rc = 0;

#ifdef WIN32
        gettimeofday(&tv, NULL);
#else
        rc = gettimeofday(&tv, NULL);
#endif
        if (rc == 0) {
/* We need this subsec buffer, because we convert
 * the integer with sprintf(), but we don't
 * want to write the terminating '\0' into our
 * final log format string.
 */
            char subsec[7];
            t = tv.tv_sec;
            strncpy(log_fmt, l->log_fmt_subsec, l->log_fmt_size + 1);
            if (l->log_fmt_type == JK_TIME_SUBSEC_MILLI) {
                sprintf(subsec, "%03d", (int)(tv.tv_usec/1000));
                strncpy(log_fmt + l->log_fmt_offset, subsec, 3);
            }
            else if (l->log_fmt_type == JK_TIME_SUBSEC_MICRO) {
                sprintf(subsec, "%06d", (int)(tv.tv_usec));
                strncpy(log_fmt + l->log_fmt_offset, subsec, 6);
            }
        }
        else {
            t = time(NULL);
        }
    }
    else {
        t = time(NULL);
    }
#else
    t = time(NULL);
#endif
#ifdef _MT_CODE_PTHREAD
    tms = localtime_r(&t, &res);
#else
    tms = localtime(&t);
#endif
    if (log_fmt[0])
        done = (int)strftime(str, len, log_fmt, tms);
    else
        done = (int)strftime(str, len, l->log_fmt, tms);
    return done;

}

static int JK_METHOD log_to_file(jk_logger_t *l, int level, int used, char *what)
{
    if (l &&
        (l->level <= level || level == JK_LOG_REQUEST_LEVEL) &&
        l->logger_private && what) {
        jk_file_logger_t *p = l->logger_private;
        if (p->logfile) {
            what[used++] = '\n';
            what[used] = '\0';
            fputs(what, p->logfile);
            /* [V] Flush the dam' thing! */
            fflush(p->logfile);
        }
        return JK_TRUE;
    }
    return JK_FALSE;
}

int jk_parse_log_level(const char *level)
{
    if (0 == strcasecmp(level, JK_LOG_TRACE_VERB)) {
        return JK_LOG_TRACE_LEVEL;
    }

    if (0 == strcasecmp(level, JK_LOG_DEBUG_VERB)) {
        return JK_LOG_DEBUG_LEVEL;
    }

    if (0 == strcasecmp(level, JK_LOG_INFO_VERB)) {
        return JK_LOG_INFO_LEVEL;
    }

    if (0 == strcasecmp(level, JK_LOG_WARN_VERB)) {
        return JK_LOG_WARNING_LEVEL;
    }

    if (0 == strcasecmp(level, JK_LOG_ERROR_VERB)) {
        return JK_LOG_ERROR_LEVEL;
    }

    if (0 == strcasecmp(level, JK_LOG_EMERG_VERB)) {
        return JK_LOG_EMERG_LEVEL;
    }

    return JK_LOG_DEF_LEVEL;
}

int jk_open_file_logger(jk_logger_t **l, const char *file, int level)
{
    if (l && file) {

        jk_logger_t *rc = (jk_logger_t *)malloc(sizeof(jk_logger_t));
        jk_file_logger_t *p = (jk_file_logger_t *) malloc(sizeof(jk_file_logger_t));
        if (rc && p) {
            rc->log = log_to_file;
            rc->level = level;
            rc->logger_private = p;
#if defined(AS400) && !defined(AS400_UTF8)
            p->logfile = fopen(file, "a+, o_ccsid=0");
#else
            p->logfile = fopen(file, "a+");
#endif
            if (p->logfile) {
                *l = rc;
                jk_set_time_fmt(rc, NULL);
                return JK_TRUE;
			} 
        }
        if (rc) {
            free(rc);
        }
        if (p) {
            free(p);
        }

        *l = NULL;
	} 
    return JK_FALSE;
}

int jk_attach_file_logger(jk_logger_t **l, int fd, int level)
{
    if (l && fd >= 0) {

        jk_logger_t *rc = (jk_logger_t *)malloc(sizeof(jk_logger_t));
        jk_file_logger_t *p = (jk_file_logger_t *) malloc(sizeof(jk_file_logger_t));
        if (rc && p) {
            rc->log = log_to_file;
            rc->level = level;
            rc->logger_private = p;
#if defined(AS400) && !defined(AS400_UTF8)
            p->logfile = fdopen(fd, "a+, o_ccsid=0");
#else
            p->logfile = fdopen(fd, "a+");
#endif
            if (p->logfile) {
                *l = rc;
                jk_set_time_fmt(rc, NULL);
                return JK_TRUE;
            }
        }
        if (rc) {
            free(rc);
        }
        if (p) {
            free(p);
        }

        *l = NULL;
    }
    return JK_FALSE;
}

int jk_close_file_logger(jk_logger_t **l)
{
    if (l && *l) {
        jk_file_logger_t *p = (*l)->logger_private;
        if (p) {
            fflush(p->logfile);
            fclose(p->logfile);
            free(p);
        }
        free(*l);
        *l = NULL;

        return JK_TRUE;
    }
    return JK_FALSE;
}

int jk_log(jk_logger_t *l,
           const char *file, int line, const char *funcname, int level,
           const char *fmt, ...)
{
    int rc = 0;
    /*
     * Need to reserve space for terminating zero byte
     * and platform specific line endings added during the call
     * to the output routing.
     */
    static int usable_size = HUGE_BUFFER_SIZE - 3;
    if (!l || !file || !fmt) {
        return -1;
    }

    if ((l->level <= level) || (level == JK_LOG_REQUEST_LEVEL)) {

#ifdef NETWARE
        /* On NetWare, this can get called on a thread that has a limited stack so */
        /* we will allocate and free the temporary buffer in this function         */
        char *buf;
#else
        char buf[HUGE_BUFFER_SIZE];
#endif
        char *f = (char *)(file + strlen(file) - 1);
        va_list args;
        int used = 0;

        while (f != file && '\\' != *f && '/' != *f) {
            f--;
        }
        if (f != file) {
            f++;
        }

#ifdef NETWARE
        buf = (char *)malloc(HUGE_BUFFER_SIZE);
        if (NULL == buf)
            return -1;
#endif
        used = set_time_str(buf, usable_size, l);

        if (line) { /* line==0 only used for request log item */
            /* Log [pid:threadid] for all levels except REQUEST. */
            /* This information helps to correlate lines from different logs. */
            /* Performance is no issue, because with production log levels */
            /* we only call it often, if we have a lot of errors */
            rc = snprintf(buf + used, usable_size - used,
                          "[%" JK_PID_T_FMT ":%" JK_UINT32_T_FMT "] ", getpid(), jk_gettid());
            used += rc;
            if (rc < 0 ) {
                return 0;
            }

            rc = (int)strlen(jk_level_verbs[level]);
            if (usable_size - used >= rc) {
                strncpy(buf + used, jk_level_verbs[level], rc);
                used += rc;
            }
            else {
                return 0;           /* [V] not sure what to return... */
            }

            if (funcname) {
                rc = (int)strlen(funcname);
                if (usable_size - used >= rc + 2) {
                    strncpy(buf + used, funcname, rc);
                    used += rc;
                    strncpy(buf + used, "::", 2);
                    used += 2;
                }
                else {
                    return 0;           /* [V] not sure what to return... */
                }
            }

            rc = (int)strlen(f);
            if (usable_size - used >= rc) {
                strncpy(buf + used, f, rc);
                used += rc;
            }
            else {
                return 0;           /* [V] not sure what to return... */
            }

            rc = snprintf(buf + used, usable_size - used,
                          " (%d): ", line);
            used += rc;
            if (rc < 0 || usable_size - used < 0) {
                return 0;           /* [V] not sure what to return... */
            }
        }

        va_start(args, fmt);
        rc = vsnprintf(buf + used, usable_size - used, fmt, args);
        va_end(args);
        if ( rc <= usable_size - used ) {
            used += rc;
        } else {
            used = usable_size;
        }
        l->log(l, level, used, buf);

#ifdef WIN32
//		syslog(level, buf);
#endif 

#ifdef NETWARE
        free(buf);
#endif
    }

    return rc;
}

void syslog(int logging_level, const char *message, ...) {

	// TODO : This could be dinamically read from Windows Registr but ...
	// For now use Debug/Release profiles to modify this ...
#ifdef _DEBUG
	int def_loggin_level = JK_LOG_DEBUG_LEVEL;
#else
	int def_loggin_level = JK_LOG_WARNING_LEVEL;
#endif 

	if (logging_level >= def_loggin_level) {
		va_list args;
		va_start(args, message);
		log_event( "JOSSO Isapi" , logging_level, message, args );
		va_end(args);
	}

}

void log_event (const char * source, int logging_level, const char * format, va_list args )
{

    char      log[BUFFSIZE];
	HANDLE hEvent;
	//PTSTR pszaStrings[1];	
	unsigned short errortype;
	DWORD eventid=JOSSO_ERR_ID_SIMPLE;

	switch (logging_level) {
	case JK_LOG_TRACE_LEVEL:
        errortype = EVENTLOG_INFORMATION_TYPE;
		eventid = JOSSO_ERR_ID_DEBUG;
        break;
	case JK_LOG_DEBUG_LEVEL:
        errortype = EVENTLOG_INFORMATION_TYPE;
		eventid = JOSSO_ERR_ID_DEBUG;
        break;
	case JK_LOG_INFO_LEVEL:
        errortype = EVENTLOG_INFORMATION_TYPE;
        break;
	case JK_LOG_WARNING_LEVEL:
		errortype = EVENTLOG_WARNING_TYPE;
		break;
	case JK_LOG_ERROR_LEVEL:
        errortype = EVENTLOG_ERROR_TYPE;
		break;
	default:
		errortype = EVENTLOG_WARNING_TYPE;
	}

	_vsnprintf(log, BUFFSIZE, format, args);


	hEvent = RegisterEventSource(NULL,source);
	if (hEvent) 
	{
		LPCSTR messages[] = {log, NULL};

		ReportEvent(hEvent, errortype, 0, eventid, NULL, 1, 0,                  
            messages, NULL);

		DeregisterEventSource(hEvent);
	}
}




int jk_stat(const char *f, struct stat * statbuf)
{
  int rc;
/**
 * i5/OS V5R4 expect filename in ASCII for fopen but required them in EBCDIC for stat()
 */
#ifdef AS400_UTF8
  char *ptr;

  ptr = (char *)malloc(strlen(f) + 1);
  jk_ascii2ebcdic((char *)f, ptr);
  rc = stat(ptr, statbuf);
  free(ptr);
#else
  rc = stat(f, statbuf);
#endif

  return (rc);
}


int jk_file_exists(const char *f)
{
    if (f) {
        struct stat st;

        if ((0 == jk_stat(f, &st)) && (st.st_mode & S_IFREG))
      return JK_TRUE;
    }

    return JK_FALSE;
}

static int jk_is_some_property(const char *prp_name, const char *suffix, const char *sep)
{
    char buf[1024];

    if (prp_name && suffix) {
        size_t prp_name_len;
        size_t suffix_len;
        strcpy(buf, sep);
        strcat(buf, suffix);
        prp_name_len = strlen(prp_name);
        suffix_len = strlen(buf);
        if (prp_name_len >= suffix_len) {
            const char *prp_suffix = prp_name + prp_name_len - suffix_len;
            if (0 == strcmp(buf, prp_suffix)) {
                return JK_TRUE;
            }
        }
    }

    return JK_FALSE;
}


int is_http_status_fail(unsigned int http_status_fail_num,
                        int *http_status_fail, int status)
{
    unsigned int i;
    int soft_status = -1 * status;
    for (i = 0; i < http_status_fail_num; i++) {
        if (http_status_fail[i] == status)
            return 1;
        else if (http_status_fail[i] == soft_status)
            return -1;
    }
    return 0;
}

char **jk_parse_sysprops(jk_pool_t *p, const char *sysprops)
{
    char **rc = NULL;
#ifdef _MT_CODE_PTHREAD
    char *lasts;
#endif

    if (p && sysprops) {
        char *prps = jk_pool_strdup(p, sysprops);
        if (prps && strlen(prps)) {
            unsigned num_of_prps;

            for (num_of_prps = 1; *sysprops; sysprops++) {
                if ('*' == *sysprops) {
                    num_of_prps++;
                }
            }

            rc = jk_pool_alloc(p, (num_of_prps + 1) * sizeof(char *));
            if (rc) {
                unsigned i = 0;
#ifdef _MT_CODE_PTHREAD
                char *tmp = strtok_r(prps, "*", &lasts);
#else
                char *tmp = strtok(prps, "*");
#endif

                while (tmp && i < num_of_prps) {
                    rc[i] = tmp;
#ifdef _MT_CODE_PTHREAD
                    tmp = strtok_r(NULL, "*", &lasts);
#else
                    tmp = strtok(NULL, "*");
#endif
                    i++;
                }
                rc[i] = NULL;
            }
        }
    }

    return rc;
}

void jk_append_libpath(jk_pool_t *p, const char *libpath)
{
    char *env = NULL;
    char *current = getenv(PATH_ENV_VARIABLE);

    if (current) {
        env = jk_pool_alloc(p, strlen(PATH_ENV_VARIABLE) +
                            strlen(current) + strlen(libpath) + 5);
        if (env) {
            sprintf(env, "%s=%s%c%s",
                    PATH_ENV_VARIABLE, libpath, PATH_SEPERATOR, current);
        }
    }
    else {
        env = jk_pool_alloc(p, strlen(PATH_ENV_VARIABLE) +
                            strlen(libpath) + 5);
        if (env) {
            sprintf(env, "%s=%s", PATH_ENV_VARIABLE, libpath);
        }
    }

    if (env) {
        putenv(env);
    }
}


/* Match = 0, NoMatch = 1, Abort = -1
 * Based loosely on sections of wildmat.c by Rich Salz
 */
int jk_wildchar_match(const char *str, const char *exp, int icase)
{
    int x, y;

    for (x = 0, y = 0; exp[y]; ++y, ++x) {
        if (!str[x] && exp[y] != '*')
            return -1;
        if (exp[y] == '*') {
            while (exp[++y] == '*');
            if (!exp[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = jk_wildchar_match(&str[x++], &exp[y], icase)) != 1)
                    return ret;
            }
            return -1;
        }
        else if (exp[y] != '?') {
            if (icase && (tolower(str[x]) != tolower(exp[y])))
                return 1;
            else if (!icase && str[x] != exp[y])
                return 1;
        }
    }
    return (str[x] != '\0');
}

#ifdef _MT_CODE_PTHREAD
jk_uint32_t jk_gettid()
{
    union {
        pthread_t tid;
        jk_uint64_t alignme;
    } u;
#ifdef AS400
    /* OS400 use 64 bits ThreadId */
    pthread_id_np_t       tid;
#endif /* AS400 */
    u.tid = pthread_self();
#ifdef AS400
    /* Get only low 32 bits for now */
    pthread_getunique_np(&(u.tid), &tid);
    return ((jk_uint32_t)(tid.intId.lo & 0xFFFFFFFF));
#else
    switch(sizeof(pthread_t)) {
    case sizeof(jk_uint32_t):
        return *(jk_uint32_t *)&u.tid;
    case sizeof(jk_uint64_t):
        return (*(jk_uint64_t *)&u.tid) & 0xFFFFFFFF;
    default:
        return 0;
    }
#endif /* AS400 */
}
#endif

/***
 * ASCII <-> EBCDIC conversions
 *
 * For now usefull only in i5/OS V5R4 where UTF and EBCDIC mode are mixed
 */

#ifdef AS400_UTF8

/* EBCDIC to ASCII translation table */
static u_char ebcdic_to_ascii[256] =
{
  0x00,0x01,0x02,0x03,0x20,0x09,0x20,0x7f, /* 00-07 */
  0x20,0x20,0x20,0x0b,0x0c,0x0d,0x0e,0x0f, /* 08-0f */
  0x10,0x11,0x12,0x13,0x20,0x0a,0x08,0x20, /* 10-17 */
  0x18,0x19,0x20,0x20,0x20,0x1d,0x1e,0x1f, /* 18-1f */
  0x20,0x20,0x1c,0x20,0x20,0x0a,0x17,0x1b, /* 20-27 */
  0x20,0x20,0x20,0x20,0x20,0x05,0x06,0x07, /* 28-2f */
  0x20,0x20,0x16,0x20,0x20,0x20,0x20,0x04, /* 30-37 */
  0x20,0x20,0x20,0x20,0x14,0x15,0x20,0x1a, /* 38-3f */
  0x20,0x20,0x83,0x84,0x85,0xa0,0xc6,0x86, /* 40-47 */
  0x87,0xa4,0xbd,0x2e,0x3c,0x28,0x2b,0x7c, /* 48-4f */
  0x26,0x82,0x88,0x89,0x8a,0xa1,0x8c,0x8b, /* 50-57 */
  0x8d,0xe1,0x21,0x24,0x2a,0x29,0x3b,0xaa, /* 58-5f */
  0x2d,0x2f,0xb6,0x8e,0xb7,0xb5,0xc7,0x8f, /* 60-67 */
  0x80,0xa5,0xdd,0x2c,0x25,0x5f,0x3e,0x3f, /* 68-6f */
  0x9b,0x90,0xd2,0xd3,0xd4,0xd6,0xd7,0xd8, /* 70-77 */
  0xde,0x60,0x3a,0x23,0x40,0x27,0x3d,0x22, /* 78-7f */
  0x9d,0x61,0x62,0x63,0x64,0x65,0x66,0x67, /* 80-87 */
  0x68,0x69,0xae,0xaf,0xd0,0xec,0xe7,0xf1, /* 88-8f */
  0xf8,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70, /* 90-97 */
  0x71,0x72,0xa6,0xa7,0x91,0xf7,0x92,0xcf, /* 98-9f */
  0xe6,0x7e,0x73,0x74,0x75,0x76,0x77,0x78, /* a8-a7 */
  0x79,0x7a,0xad,0xa8,0xd1,0xed,0xe8,0xa9, /* a8-af */
  0x5e,0x9c,0xbe,0xfa,0xb8,0x15,0x14,0xac, /* b0-b7 */
  0xab,0xf3,0x5b,0x5d,0xee,0xf9,0xef,0x9e, /* b8-bf */
  0x7b,0x41,0x42,0x43,0x44,0x45,0x46,0x47, /* c0-c7 */
  0x48,0x49,0xf0,0x93,0x94,0x95,0xa2,0xe4, /* c8-cf */
  0x7d,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50, /* d0-d7 */
  0x51,0x52,0xfb,0x96,0x81,0x97,0xa3,0x98, /* d8-df */
  0x5c,0xf6,0x53,0x54,0x55,0x56,0x57,0x58, /* e0-e7 */
  0x59,0x5a,0xfc,0xe2,0x99,0xe3,0xe0,0xe5, /* e8-ef */
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37, /* f0-f7 */
  0x38,0x39,0xfd,0xea,0x9a,0xeb,0xe9,0xff  /* f8-ff */
};

/* ASCII to EBCDIC translation table */
static u_char ascii_to_ebcdic[256] =
{
  0x00,0x01,0x02,0x03,0x37,0x2d,0x2e,0x2f, /* 00-07 */
  0x16,0x05,0x25,0x0b,0x0c,0x0d,0x0e,0x0f, /* 08-0f */
  0x10,0x11,0x12,0x13,0x3c,0x3d,0x32,0x26, /* 10-17 */
  0x18,0x19,0x3f,0x27,0x22,0x1d,0x1e,0x1f, /* 18-1f */
  0x40,0x5a,0x7f,0x7b,0x5b,0x6c,0x50,0x7d, /* 20-27 */
  0x4d,0x5d,0x5c,0x4e,0x6b,0x60,0x4b,0x61, /* 28-2f */
  0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7, /* 30-37 */
  0xf8,0xf9,0x7a,0x5e,0x4c,0x7e,0x6e,0x6f, /* 38-3f */
  0x7c,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7, /* 40-47 */
  0xc8,0xc9,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6, /* 48-4f */
  0xd7,0xd8,0xd9,0xe2,0xe3,0xe4,0xe5,0xe6, /* 50-57 */
  0xe7,0xe8,0xe9,0xba,0xe0,0xbb,0xb0,0x6d, /* 58-5f */
  0x79,0x81,0x82,0x83,0x84,0x85,0x86,0x87, /* 60-67 */
  0x88,0x89,0x91,0x92,0x93,0x94,0x95,0x96, /* 68-6f */
  0x97,0x98,0x99,0xa2,0xa3,0xa4,0xa5,0xa6, /* 70-77 */
  0xa7,0xa8,0xa9,0xc0,0x4f,0xd0,0xa1,0x07, /* 78-7f */
  0x68,0xdc,0x51,0x42,0x43,0x44,0x47,0x48, /* 80-87 */
  0x52,0x53,0x54,0x57,0x56,0x58,0x63,0x67, /* 88-8f */
  0x71,0x9c,0x9e,0xcb,0xcc,0xcd,0xdb,0xdd, /* 90-97 */
  0xdf,0xec,0xfc,0x70,0xb1,0x80,0xbf,0x40, /* 98-9f */
  0x45,0x55,0xee,0xde,0x49,0x69,0x9a,0x9b, /* a8-a7 */
  0xab,0xaf,0x5f,0xb8,0xb7,0xaa,0x8a,0x8b, /* a8-af */
  0x40,0x40,0x40,0x40,0x40,0x65,0x62,0x64, /* b0-b7 */
  0xb4,0x40,0x40,0x40,0x40,0x4a,0xb2,0x40, /* b8-bf */
  0x40,0x40,0x40,0x40,0x40,0x40,0x46,0x66, /* c0-c7 */
  0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x9f, /* c8-cf */
  0x8c,0xac,0x72,0x73,0x74,0x89,0x75,0x76, /* d0-d7 */
  0x77,0x40,0x40,0x40,0x40,0x6a,0x78,0x40, /* d8-df */
  0xee,0x59,0xeb,0xed,0xcf,0xef,0xa0,0x8e, /* e0-e7 */
  0xae,0xfe,0xfb,0xfd,0x8d,0xad,0xbc,0xbe, /* e8-ef */
  0xca,0x8f,0x40,0xb9,0xb6,0xb5,0xe1,0x9d, /* f0-f7 */
  0x90,0xbd,0xb3,0xda,0xea,0xfa,0x40,0x40  /* f8-ff */
};

void jk_ascii2ebcdic(char *src, char *dst) {
    char c;

    while ((c = *src++) != 0) {
        *dst++ = ascii_to_ebcdic[(unsigned int)c];
    }

    *dst = 0;
}

void jk_ebcdic2ascii(char *src, char *dst) {
    char c;

    while ((c = *src++) != 0) {
        *dst++ = ebcdic_to_ascii[(unsigned int)c];
    }

    *dst = 0;
}

#endif
