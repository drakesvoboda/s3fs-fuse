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
#include "openssl_enc.h"
#include "string_util.h"

#include "zstd_compress.h"

ssize_t CompressUtil::do_compress(CompressContext * ctx, const void * inbuff, size_t buffsize, void * outbuff)
{
 return -1;
}

ssize_t CompressUtil::do_decompress(CompressContext * ctx, const void * inbuff, size_t buffsize, void * outbuff)
{
  return -1;
}

void CompressContext::init()
{
  if(this->do_compress){
    cstream = ZSTD_createCStream();
    if(cstream == NULL)
      S3FS_PRN_ERR("ZSTD_createCStream error");

    size_t const initresult = ZSTD_initCStream(cstream, CompressContext::COMPRESSION_LEVEL);

    if(ZSTD_isError(initresult)) 
      S3FS_PRN_ERR("ZSTD_initCStream() err: %s", ZSTD_getErrorName(initresult));
  }else{
    ZSTD_DStream* const dstream = ZSTD_createDStream();
    if(dstream == NULL)
      S3FS_PRN_INFO("ZSTD_createDStream() error");
  }

  this->initialized = true;
}
