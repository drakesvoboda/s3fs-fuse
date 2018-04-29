#include "openssl_enc.h"
#include "zstd_compress.h"
#include "comp_and_crypt.h"

ssize_t CompCryptUtil::DownloadWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp)
{
  CompCryptContext * ctx = reinterpret_cast<CompCryptContext*>(userp);

  size_t requested_size = size * nmemb;

  S3FS_PRN_INFO("[sent: %ld][remaining: %ld]", requested_size, ctx->bytes_remaining);

  size_t copysize = ((ssize_t)requested_size < ctx->bytes_remaining) ? requested_size : ctx->bytes_remaining;
  ssize_t totalwrite;
  size_t toread;

  totalwrite = DecryptDecompressWrite(ctx, ptr, copysize, &toread); 

  if(totalwrite == -1){
    S3FS_PRN_ERR("DecryptDecompressWrite() err");
    return -1;
  }

  ctx->bytes_remaining -= copysize;

  if(ctx->bytes_remaining < 1 && !ctx->cryptctx->finished){
    totalwrite += DecryptDecompressWriteFinal(ctx);
  }

  S3FS_PRN_INFO("[sent: %ld][written: %ld][remaining: %ld]", requested_size, totalwrite, ctx->bytes_remaining);
  return copysize;
}

ssize_t CompCryptUtil::DecryptDecompressWrite(CompCryptContext * ctx, void * inbuff, size_t numbytes, size_t * toread)
{
  size_t cryptbuffsize = numbytes;
  void * cryptbuff = (void *)malloc(cryptbuffsize + EVP_MAX_BLOCK_LENGTH);

  size_t pressbuffsize = ZSTD_DStreamOutSize();
  void * pressbuff = (void *)malloc(pressbuffsize);

  if(cryptbuff == NULL || pressbuff == NULL){
    S3FS_PRN_ERR("Error allocating buffer");
    return -1;
  }

  ssize_t cryptlen, writelen, totalwrite = 0;

  cryptlen = CryptUtil::do_crypt(ctx->cryptctx, inbuff, numbytes, cryptbuff);

  if(cryptlen == -1){
    S3FS_PRN_ERR("Error decrypting");
    return -1;
  }

  ZSTD_inBuffer input = {cryptbuff, (size_t)cryptlen, 0};
  while(input.pos < input.size){
    ZSTD_outBuffer output = {pressbuff, pressbuffsize, 0};
    *toread = ZSTD_decompressStream(ctx->pressctx->dstream, &output, &input);

    if(ZSTD_isError(*toread)){
      S3FS_PRN_ERR("Error decompressing (%s)", ZSTD_getErrorName(*toread));
      return -1;
    }

    writelen = pwrite(ctx->outfd, pressbuff, output.pos, ctx->bytes_written + totalwrite);
    totalwrite += writelen;
    
    if(writelen == -1){
      S3FS_PRN_ERR("Error writing to file");
      return -1;
    }
  }

  free(cryptbuff);
  free(pressbuff);

  ctx->bytes_written += totalwrite;

  return totalwrite;
}

ssize_t CompCryptUtil::DecryptDecompressWriteFinal(CompCryptContext * ctx)
{
  size_t cryptbuffsize = EVP_MAX_BLOCK_LENGTH;
  void * cryptbuff = (void *)malloc(cryptbuffsize);

  size_t pressbuffsize = ZSTD_DStreamOutSize();
  void * pressbuff = (void *)malloc(pressbuffsize);

  if(cryptbuff == NULL || pressbuff == NULL){
    S3FS_PRN_ERR("Error allocating buffer");
    return -1;
  }

  ssize_t toread, cryptlen, writelen, totalwrite = 0;

  cryptlen = CryptUtil::do_crypt(ctx->cryptctx, NULL, 0, cryptbuff);

  if(cryptlen == -1){
    S3FS_PRN_ERR("Error decrypting");
    return -1;
  }

  ZSTD_inBuffer input = {cryptbuff, (size_t)cryptlen, 0};
  while(input.pos < input.size){
    ZSTD_outBuffer output = {pressbuff, pressbuffsize, 0};
    toread = ZSTD_decompressStream(ctx->pressctx->dstream, &output, &input);

    if(ZSTD_isError(toread)){
      S3FS_PRN_ERR("Error decompressing (%s)", ZSTD_getErrorName(toread));
      return -1;
    }

    writelen = pwrite(ctx->outfd, pressbuff, output.pos, ctx->bytes_written + totalwrite);
    
    if(writelen == -1){
      S3FS_PRN_ERR("Error writing to file");
      return -1;
    }

    totalwrite += writelen;
  }

  free(cryptbuff);
  free(pressbuff);

  ctx->bytes_written += totalwrite;
  ctx->pressctx->finished = true;
  ctx->cryptctx->finished = true;

  return totalwrite;
}


ssize_t CompCryptUtil::CompressEncryptWrite(CompCryptContext * ctx, void * inbuff, size_t numbytes, size_t * toread)
{
  size_t const pressbuffsize = ZSTD_CStreamOutSize();
  void * pressbuff = (void *)malloc(pressbuffsize);

  size_t const cryptbuffsize = pressbuffsize;
  void * cryptbuff = (void *)malloc(cryptbuffsize + EVP_MAX_BLOCK_LENGTH);

  if(pressbuff == NULL || cryptbuff == NULL){
    S3FS_PRN_ERR("Error allocating buffer");
    return -1;
  }

  ssize_t writelen, cryptlen, totalwrite = 0;

  ZSTD_inBuffer input = {inbuff, numbytes, 0};
  while(input.pos < input.size){
    ZSTD_outBuffer output = {pressbuff, pressbuffsize, 0};
    *toread = ZSTD_compressStream(ctx->pressctx->cstream, &output, &input);

    if(ZSTD_isError(*toread)){
      S3FS_PRN_ERR("Compression Error (%s)", ZSTD_getErrorName(*toread));
      return -1;
    }

    if(output.pos > 0){ // We have some bytes to encrypt and write
      cryptlen = CryptUtil::do_crypt(ctx->cryptctx, pressbuff, output.pos, cryptbuff); 

      if(cryptlen == -1){
        S3FS_PRN_ERR("Error during encryption");
        return -1;
      }

      writelen = pwrite(ctx->outfd, cryptbuff, cryptlen, ctx->bytes_written + totalwrite);
      totalwrite += writelen;
      
      if(writelen == -1){
        S3FS_PRN_ERR("Error while writing to file");
        return -1;
      }
    }
  }

  ctx->bytes_written += totalwrite;

  free(cryptbuff);
  free(pressbuff);

  return totalwrite;
}

ssize_t CompCryptUtil::CompressEncryptWriteFinal(CompCryptContext * ctx)
{
  size_t const pressbuffsize = ZSTD_CStreamOutSize();
  void * pressbuff = (void *)malloc(pressbuffsize);

  size_t const cryptbuffsize = pressbuffsize;
  void * cryptbuff = (void *)malloc(cryptbuffsize + EVP_MAX_BLOCK_LENGTH);

  if(pressbuff == NULL || cryptbuff == NULL){
    S3FS_PRN_ERR("Error allocating buffer");
    return -1;
  }

  ssize_t writelen, cryptlen, totalwrite = 0;

  ZSTD_outBuffer output = {pressbuff, pressbuffsize, 0};
  size_t const remaining = ZSTD_endStream(ctx->pressctx->cstream, &output);
  if(remaining){
    S3FS_PRN_ERR("not fully flushed");
    return -1;
  }

  if(output.pos > 0){ // We have some bytes to encrypt and write
    cryptlen = CryptUtil::do_crypt(ctx->cryptctx, pressbuff, output.pos, cryptbuff); 

    if(cryptlen == -1){
      S3FS_PRN_ERR("Error during encryption");
      return -1;
    }

    writelen = pwrite(ctx->outfd, cryptbuff, cryptlen, ctx->bytes_written + totalwrite);
    totalwrite += writelen;
    
    if(writelen == -1){
      S3FS_PRN_ERR("Error while writing to file");
      return -1;
    }
  }

  cryptlen = CryptUtil::do_crypt(ctx->cryptctx, NULL, 0, cryptbuff); // Finalize encryption

  if(cryptlen == -1){
    S3FS_PRN_ERR("Error during encryption");
    return -1;
  }

  writelen = pwrite(ctx->outfd, cryptbuff, cryptlen, ctx->bytes_written + totalwrite);
  totalwrite += writelen;
  
  if(writelen == -1){
    S3FS_PRN_ERR("Error while writing to file");
    return -1;
  }

  ctx->pressctx->finished = true;  
  ctx->cryptctx->finished = true;

  ctx->bytes_written += totalwrite;

  free(pressbuff);
  free(cryptbuff);

  return writelen;
}

ssize_t CompCryptUtil::CompressEncryptFile(CompCryptContext * ctx)
{
  size_t const readbuffsize = ZSTD_CStreamInSize();
  void * readbuff = (void *)malloc(readbuffsize);

  if(readbuff == NULL){
    S3FS_PRN_ERR("Could not allocate buffer");
    return -1;
  }

  size_t totalread = 0, toread = readbuffsize;
  ssize_t readlen;

  for(;;){
    readlen = pread(ctx->infd, readbuff, toread, totalread);
    totalread += readlen;

    if(readlen == 0) break; //We have finished reading the input
    if(readlen == -1){
      S3FS_PRN_ERR("Error while reading from file (%d)", errno);
    }

    CompressEncryptWrite(ctx, readbuff, readlen, &toread);

    if(toread > readbuffsize) toread = readbuffsize;
  }

  CompressEncryptWriteFinal(ctx);

  free(readbuff);
    
  return ctx->bytes_written;
}
