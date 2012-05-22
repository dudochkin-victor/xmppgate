#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#define DEBUG_BUF_MAX		4096
#define DEBUG_FLUSH_SIZE	 1

#define DEBUG_INIT(LEVEL, LOGPATH, REV) { debugInit(LEVEL, LOGPATH); MSG("started: " REV); }
#define DEBUG_DONE() { MSG("finished"); debugDone(); }

#define MSG(A,...) debugMsg(DL_MSG, __FILE__, __LINE__, __FUNCTION__, A, ## __VA_ARGS__)
#define FATAL(A,...) { debugMsg(DL_FATAL, __FILE__, __LINE__, __FUNCTION__, A, ## __VA_ARGS__); assert(0); }
#define WARN(A,...) debugMsg(DL_WARN, __FILE__, __LINE__, __FUNCTION__, A, ## __VA_ARGS__)
#define INFO(A,...) debugMsg(DL_INFO, __FILE__, __LINE__, __FUNCTION__, A, ## __VA_ARGS__)
#define DEBUG(A,...) debugMsg(DL_DEBUG, __FILE__, __LINE__, __FUNCTION__, A, ## __VA_ARGS__)

typedef enum {
  DL_SILENT    = 0,
  DL_MSG       = 1,
  DL_FATAL     = 2,
  DL_WARN      = 3,
  DL_INFO      = 4,
  DL_DEBUG     = 5
} debugLevel_t;

extern pid_t        debugPid;
extern pthread_t    debugThid;
extern debugLevel_t debugLevel;
extern FILE         *debugFile;

int debugInit(debugLevel_t level, const char *fn);
void debugDone(void);
void debugMsg(debugLevel_t level, const char *file, int line, const char *func, const char *msg, ...);
void debugFlush(void);

#endif
