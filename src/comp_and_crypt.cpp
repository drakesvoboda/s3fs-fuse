#include "openssl_enc.h"
#include "zstd_compress.h"
#include "comp_and_crypt.h"

ssize_t CompCryptUtil::DownloadWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp)
{
  CompCryptContext * ctx = reinterpret_cast<CompCryptContext*>(userp);

  size_t requested_size = size * nmemb;

  S3FS_PRN_INFO("[sent: %ld][remaining: %ld]", requested_size, ctx->bytes_remaining);

  ssize_t cryptlen, writelen, totalwrite = 0;
  size_t copysize = ((ssize_t)requested_size < ctx->bytes_remaining) ? requested_size : ctx->bytes_remaining;

  unsigned char * outbuff = new unsigned char[copysize + EVP_MAX_BLOCK_LENGTH];

  if(ctx->outfd == -1){
	S3FS_PRN_ERR("Missing file descriptor for write.");
	return -1;
  }

  if(copysize > 0){	
	cryptlen = CryptUtil::do_crypt(ctx->cryptctx, ptr, copysize, (void *)outbuff);

    if (cryptlen == -1){
	  S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
    }

    writelen = pwrite(ctx->outfd, (const void *)outbuff, cryptlen, ctx->bytes_written + totalwrite);

    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
    }

	totalwrite += writelen;
  }

  ctx->bytes_remaining -= copysize;

  if(ctx->bytes_remaining < 1 && !ctx->cryptctx->finished){
    cryptlen = CryptUtil::do_crypt(ctx->cryptctx, (unsigned char*)ptr, 0, outbuff);

    if (cryptlen == -1){
	  S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
    }

    writelen = pwrite(ctx->outfd, (const void *)outbuff, cryptlen, ctx->bytes_written + totalwrite);

    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
    }

    totalwrite += writelen;
  }

  ctx->bytes_written += totalwrite;

  S3FS_PRN_INFO("[sent: %ld][written: %ld][remaining: %ld]", requested_size, totalwrite, ctx->bytes_remaining);
  return totalwrite;
}

ssize_t CompCryptUtil::DecryptDecompressFile(CompCryptContext * ctx)
{
  return CryptUtil::crypt_file(ctx->cryptctx);
}

ssize_t CompCryptUtil::CompressEncryptFile(CompCryptContext * ctx)
{
  size_t const inbuffsize = ZSTD_CStreamInSize();
  void * inbuff = (void *)malloc(inbuffsize);

  size_t pressbuffsize = inbuffsize;
  void * pressbuff = (void *)malloc(pressbuffsize);

  size_t outbuffsize = inbuffsize;
  void * outbuff = (void *)malloc(outbuffsize);

  if(inbuff == NULL || pressbuff == NULL || outbuff == NULL)
    S3FS_PRN_ERR("Could not allocate in buffer");

  size_t readlen, toread = inbuffsize, totalread = 0;
  size_t tocrypt, towrite, writelen;

  for(;;totalread += readlen, ctx->bytes_written += writelen){
    readlen = pread(ctx->infd, inbuff, toread, totalread);

    if(readlen == 0) break; //We have finished reading the input
    if(readlen == -1){
      S3FS_PRN_ERR("Error while reading from file (%d)", errno);
    }
    
    tocrypt = CompressUtil::do_compress(ctx->pressctx, inbuff, readlen, &pressbuff, &pressbuffsize, &toread);

    if(tocrypt == -1){
      S3FS_PRN_ERR("Error while compressing");
      return -1;
    }

    if(toread > inbuffsize) toread = inbuffsize;

    if(pressbuffsize > outbuffsize){
      outbuffsize = pressbuffsize;
      void * temp = (void *)realloc(outbuff, outbuffsize);
      if(temp)
        outbuff = temp;
      else{
        S3FS_PRN_ERR("Error while reallocating");
        return -1;
      }
    }

    towrite = CryptUtil::do_crypt(ctx->cryptctx, pressbuff, pressbuffsize, outbuff);

    if(towrite == -1){
      S3FS_PRN_ERR("Error while encrypting");
      return -1;
    }

    writelen = pwrite(ctx->outfd, outbuff, towrite, ctx->bytes_written);

    if(writelen == -1){
      S3FS_PRN_ERR("Error writing to file");
      return -1;
    }
  }
  

  //TODO: FINISH METHOD


  free(inbuff);
  free(outbuff);
}
