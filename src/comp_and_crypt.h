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

  int infd, outfd;

  ssize_t bytes_remaining; // Keeps track of remaining bytes to be downloaded.
  ssize_t bytes_written;

  bool do_upload; //True: Compress-Encrypt , False: Decrypt-Decompress

  CompCryptContext(int infd, size_t insize, int outfd, bool do_upload):
    pressctx(new CompressContext(infd, outfd, do_upload)),
    cryptctx(new CryptContext(infd, outfd, do_upload)),
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
    if(!cryptctx->initialized){
      cryptctx->init();
    }
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
  // Used by cUrl. Processes bytes as they are downloaded
  static ssize_t DownloadWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp);

  static ssize_t CompressEncryptFile(CompCryptContext * ctx);

  static ssize_t CompressEncryptWrite(CompCryptContext * ctx, void * inbuff, size_t numbytes, size_t * toread);
  static ssize_t CompressEncryptWriteFinal(CompCryptContext * ctx);
  static ssize_t DecryptDecompressWrite(CompCryptContext * ctx, void * inbuff, size_t numbytes, size_t * toread);

  static ssize_t DecryptDecompressWriteFinal(CompCryptContext * ctx);
};

#endif
