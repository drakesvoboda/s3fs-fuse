#ifndef COMPRESSUTIL_H 
#define COMPRESSUTIL_H

#include <openssl/evp.h>
#include <openssl/rand.h>
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
friend class CompressUtil;
private:
  const static int COMPRESSION_LEVEL = 1;
public:
  ZSTD_CStream * cstream;
  ZSTD_DStream * dstream;

  bool do_compress;
  bool initialized;
  bool finished;

  CompressContext(bool do_compress) : 
    cstream(NULL), 
    dstream(NULL), 
    do_compress(do_compress), 
    initialized(false), 
    finished(false) 
  { }

  ~CompressContext()
  {
    if(cstream != NULL)
      ZSTD_freeCStream(cstream);
    if(dstream != NULL)
      ZSTD_freeDStream(dstream);
  }

  void init();
};

class CompressUtil {
friend class CompressContext;
public:
  static ssize_t do_compress(CompressContext * ctx, const void * inbuff, size_t buffsize, void * outbuff);
  static ssize_t do_decompress(CompressContext * ctx, const void * inbuff, size_t buffsize, void * outbuff);
};

#endif
