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

ssize_t CompressUtil::do_compress(CompressContext * ctx, 
    void * inbuff, size_t inbuffsize, void ** outbuff, size_t * outbuffsize, size_t * toread)
{
  size_t const internalsize = ZSTD_CStreamOutSize();
  void * internalbuff = (void *)malloc(internalsize);
  if(internalbuff == NULL){
    S3FS_PRN_ERR("Could notallocate out buffer");
    return -1;
  }

  void * temp;

  size_t totalcopy = 0;

  if(inbuffsize > 0 && inbuff != NULL){
    ZSTD_inBuffer input = {inbuff, inbuffsize, 0};
    for(;input.pos < input.size;){
      ZSTD_outBuffer output = {internalbuff, internalsize, 0};

      *toread = ZSTD_compressStream(ctx->cstream, &output, &input);

      if(ZSTD_isError(*toread)){
        S3FS_PRN_ERR("ZSTD_compressStream() err: %s", ZSTD_getErrorName(*toread));
        return -1;
      }

      totalcopy += output.pos;

      if(totalcopy > *outbuffsize){ // We need to reallocate
        *outbuffsize += (totalcopy - *outbuffsize) * 2;
        temp = realloc(*outbuff, *outbuffsize);
        if(temp)
          *outbuff = temp;
        else{
          S3FS_PRN_ERR("Error reallocating");
          return -1;
        }
      }

      memcpy((char *)*outbuff + totalcopy, &internalbuff, output.pos);
    }
  }else{
    ZSTD_outBuffer output = {outbuff, *outbuffsize, 0};

    size_t const remaining = ZSTD_endStream(ctx->cstream, &output);
    
    if(remaining){
      S3FS_PRN_ERR("Not fully flushed")
      return -1;
    }

    totalcopy += output.pos;

    if(totalcopy > *outbuffsize){ // We need to reallocate
      *outbuffsize += (totalcopy - *outbuffsize);
      temp = realloc(*outbuff, *outbuffsize);
      if(temp)
        *outbuff = temp;
      else{
        S3FS_PRN_ERR("Error reallocating");
        return -1;
      }
    }

    memcpy((char *)*outbuff + totalcopy, &internalbuff, output.pos);

    ctx->finished = true;
  }

  free(internalbuff);

  return totalcopy;
}

ssize_t CompressUtil::do_decompress(CompressContext * ctx, 
    void * inbuff, size_t inbuffsize, void ** outbuff, size_t * outbuffsize, size_t * toread)
{
  size_t const internalsize = ZSTD_CStreamOutSize();
  void * internalbuff = (void *)malloc(internalsize);
  if(internalbuff == NULL){
    S3FS_PRN_ERR("Could not allocate out buffer");
    return -1;
  }

  void * temp;

  size_t totalcopy = 0;

  if(inbuffsize > 0 && inbuff != NULL){
    ZSTD_inBuffer input = {inbuff, inbuffsize, 0};
    for(;input.pos < input.size;){
      ZSTD_outBuffer output = {internalbuff, internalsize, 0};

      *toread = ZSTD_decompressStream(ctx->dstream, &output, &input);

      if(ZSTD_isError(*toread)){
        S3FS_PRN_ERR("ZSTD_compressStream() err: %s", ZSTD_getErrorName(*toread));
        return -1;
      }

      totalcopy += output.pos;

      if(totalcopy > *outbuffsize){ // We need to reallocate
        *outbuffsize += (totalcopy - *outbuffsize) * 2;
        temp = realloc(*outbuff, (int)(*outbuffsize));
        if(temp)
          *outbuff = temp;
        else{
          S3FS_PRN_ERR("Error reallocating");
          return -1;
        }
      }

      memcpy((char *)*outbuff + totalcopy, &internalbuff, output.pos);
    }
  }else{
    ctx->finished = true;
  }

  free(internalbuff);

  return totalcopy;
}

ssize_t CompressUtil::compress_file(CompressContext * ctx)
{
  size_t const inbuffsize = ZSTD_CStreamInSize();
  void * inbuff = (void *)malloc(inbuffsize);

  size_t outbuffsize = inbuffsize;
  void * outbuff = (void *)malloc(outbuffsize);

  if(inbuff == NULL || outbuff == NULL){
    S3FS_PRN_ERR("Could not allocate in buffer");
    return -1;
  }

  ssize_t readlen, towrite, writelen;
  size_t toread = inbuffsize, totalread = 0;

  for(;;totalread += readlen, ctx->bytes_written += writelen){
    readlen = pread(ctx->infd, inbuff, toread, totalread);

    if(readlen == 0) break; //We have finished reading the input
    else if(readlen == -1){
      S3FS_PRN_ERR("Error reading from file(%d)", errno);
      return -1;
    }
    
    towrite = do_compress(ctx, inbuff, (size_t)readlen, &outbuff, &outbuffsize, &toread);

    if(towrite == -1){
      S3FS_PRN_ERR("Error during compression");
      return -1;
    }

    if(toread > inbuffsize) toread = inbuffsize;

    writelen = pwrite(ctx->outfd, outbuff, towrite, ctx->bytes_written);

    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
	}
  }

  towrite = do_compress(ctx, NULL, 0, &outbuff, &outbuffsize, &toread);
  
  writelen = pwrite(ctx->outfd, outbuff, towrite, ctx->bytes_written);

  ctx->bytes_written = writelen;

  free(inbuff);
  free(outbuff);

  return ctx->bytes_written;
}

ssize_t CompressUtil::decompress_file(CompressContext * ctx)
{
  size_t const inbuffsize = ZSTD_CStreamInSize();
  void * inbuff = (void *)malloc(inbuffsize);

  size_t outbuffsize = inbuffsize;
  void * outbuff = (void *)malloc(outbuffsize);

  if(inbuff == NULL || outbuff == NULL){
    S3FS_PRN_ERR("Could not allocate in buffer");
    return -1;
  }

  ssize_t readlen, towrite, writelen;
  size_t toread = inbuffsize, totalread = 0;

  for(;;totalread += readlen, ctx->bytes_written += writelen){
    readlen = pread(ctx->infd, inbuff, toread, totalread);

    if(readlen == 0) break;
	else if(readlen == -1){
	  S3FS_PRN_ERR("Error reading from file(%d)", errno); 
	  return -1;
	}

    towrite = do_decompress(ctx, inbuff, (size_t)readlen, &outbuff, &outbuffsize, &toread);

    if(towrite == -1){
      S3FS_PRN_ERR("Error during decompression");
      return -1;
    }

    if(toread > inbuffsize) toread = inbuffsize;

    writelen = pwrite(ctx->outfd, outbuff, towrite, ctx->bytes_written);

    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
	}
  }

  ctx->finished = true;

  free(inbuff);
  free(outbuff);

  return ctx->bytes_written;
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
