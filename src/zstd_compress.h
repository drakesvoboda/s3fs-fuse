#ifndef COMPRESSUTIL_H 
#define COMPRESSUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <curl/curl.h>
#include <algorithm>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <list>
#include <vector>
#include <zstd.h>

#include "common.h"
#include "string_util.h"

class CompressContext {
private:
  const static int COMPRESSION_LEVEL = 1;
public:
  ZSTD_CStream * cstream;
  ZSTD_DStream * dstream;

  bool do_compress;
  bool initialized;
  bool finished;

  CompressContext(int infd, int outfd, bool do_compress) : 
    cstream(NULL), 
    dstream(NULL), 
    do_compress(do_compress), 
    initialized(false), 
    finished(false) 
  {
    if(this->do_compress){
      cstream = ZSTD_createCStream();

      if(cstream == NULL)
        S3FS_PRN_ERR("ZSTD_createCStream error");

      size_t const initresult = ZSTD_initCStream(cstream, CompressContext::COMPRESSION_LEVEL);

      if(ZSTD_isError(initresult)) 
        S3FS_PRN_ERR("ZSTD_initCStream() err: %s", ZSTD_getErrorName(initresult));
    }else{
      dstream = ZSTD_createDStream();

      if(dstream == NULL)
        S3FS_PRN_INFO("ZSTD_createDStream() error");
    }

    this->initialized = true;
  }

  ~CompressContext()
  {
    if(cstream != NULL)
      ZSTD_freeCStream(cstream);
    if(dstream != NULL)
      ZSTD_freeDStream(dstream);
  }
};

#endif
