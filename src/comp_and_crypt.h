#ifndef COMPANDENC_H
#define COMPANDENC_H

#include "openssl_enc.h"
#include "zstd_compress.h"

class CompCryptContext
{
friend class CompCryptUtil;
public:

  CompressContext * pressctx;
  CryptContext * cryptctx;

  int infd;
  int outfd;

  ssize_t bytes_remaining;
  ssize_t bytes_written;

  bool do_upload; //True: Compress-Encrypt , False: Decrypt-Decompress

  CompCryptContext(int infd, size_t insize, int outfd, bool do_upload):
    pressctx(new CompressContext(do_upload)),
    cryptctx(new CryptContext(do_upload)),
    infd(infd),
    outfd(outfd),
    bytes_remaining(insize),
    bytes_written(0)
  { }

  ~CompCryptContext()
  {
    delete pressctx;
    delete cryptctx;
  }

  void init()
  {
    pressctx->init();
    cryptctx->init();
  }

  bool initialized()
  {
    return pressctx->initialized && cryptctx->initialized;
  }

  bool finished()
  {
    return pressctx->finished && cryptctx->finished;
  }
};

class CompCryptUtil
{
friend class CompCryptContext;
public:
  static ssize_t DownloadWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp);
  static ssize_t ProcessFile(CompCryptContext * ctx);
};

#endif
