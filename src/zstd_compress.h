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

  int infd, outfd;

  int bytes_written;

  bool do_compress;
  bool initialized;
  bool finished;

  CompressContext(int infd, int outfd, bool do_compress) : 
    cstream(NULL), 
    dstream(NULL), 
    infd(infd),
    outfd(outfd),
    bytes_written(0),
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

class CompressUtil {
friend class CompressContext;
public:
  // Compresses bytes from inbuff into outbuff. May reallocate outbuff. 
  // toread is set to recommended number of bytes to input next call
  static ssize_t do_compress(CompressContext * ctx, 
        void * inbuff, size_t inbuffsize, void ** outbuff, size_t * outbuffsize, size_t * toread);

  static ssize_t do_compress_final(CompressContext * ctx, void ** outbuff, size_t * outbuffsize);

  // Decompresses bytes from inbuff into outbuff. May reallocate outbuff. 
  // toread is set to recommended number of bytes to input next call
  static ssize_t do_decompress(CompressContext * ctx, 
        void * inbuff, size_t inbuffsize, void ** outbuff, size_t * outbuffsize, size_t * toread);

  static ssize_t compress_file(CompressContext * ctx);
  static ssize_t decompress_file(CompressContext * ctx);
};

#endif
