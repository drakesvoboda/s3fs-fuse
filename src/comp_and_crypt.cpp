#include "openssl_enc.h"
#include "zstd_compress.h"
#include "comp_and_crypt.h"

ssize_t CompCryptUtil::DownloadWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp)
{
  CompCryptContext * ctx = reinterpret_cast<CompCryptContext*>(userp);

  size_t requested_size = size * nmemb;

  S3FS_PRN_INFO("[sent: %ld][remaining: %ld]", requested_size, ctx->bytes_remaining);

  size_t copysize = ((ssize_t)requested_size < ctx->bytes_remaining) ? requested_size : ctx->bytes_remaining;

  ssize_t topress, towrite, writelen;
  size_t totalwrite = 0, toread = copysize;

  size_t cryptbuffsize = copysize;
  void * cryptbuff = (void*)malloc(cryptbuffsize + EVP_MAX_BLOCK_LENGTH);

  size_t pressbuffsize = copysize * 4;
  void * pressbuff = (void*)malloc(pressbuffsize);

  if(ctx->outfd == -1){
	S3FS_PRN_ERR("Missing file descriptor for write.");
	return -1;
  }

  if(copysize > 0){	
	topress = CryptUtil::do_crypt(ctx->cryptctx, ptr, cryptbuffsize, cryptbuff);

    if(topress == -1){
	  S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
    }

    towrite = CompressUtil::do_decompress(ctx->pressctx, cryptbuff, topress, &pressbuff, &pressbuffsize, &toread);

    if(towrite == -1){
      S3FS_PRN_ERR("Error while decompressing");
      return -1;
    }

    writelen = pwrite(ctx->outfd, pressbuff, towrite, ctx->bytes_written + totalwrite);

    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
    }

	totalwrite += writelen;
  }

  ctx->bytes_remaining -= copysize;

  if(ctx->bytes_remaining < 1 && !ctx->cryptctx->finished){
    topress = CryptUtil::do_crypt(ctx->cryptctx, ptr, 0, cryptbuff);

    if(topress == -1){
	  S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
    }

    towrite = CompressUtil::do_decompress(ctx->pressctx, cryptbuff, topress, &pressbuff, &pressbuffsize, &toread);

    if(towrite == -1){
      S3FS_PRN_ERR("Error while decompressing");
      return -1;
    }

    writelen = pwrite(ctx->outfd, pressbuff, towrite, ctx->bytes_written + totalwrite);

    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
    }

    totalwrite += writelen;

    if(!ctx->pressctx->finished){
      towrite = CompressUtil::do_decompress(ctx->pressctx, NULL, 0, &pressbuff, &pressbuffsize, &toread);

      if(towrite == -1){
        S3FS_PRN_ERR("Error while decompressing");
        return -1;
      }

      writelen = pwrite(ctx->outfd, pressbuff, towrite, ctx->bytes_written + totalwrite);

      if(writelen == -1){
	    S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	    return -1;
      }

      totalwrite += writelen;
    }
  }

  ctx->bytes_written += totalwrite;

  free(pressbuff);
  free(cryptbuff);

  S3FS_PRN_INFO("[sent: %ld][written: %ld][remaining: %ld]", requested_size, totalwrite, ctx->bytes_remaining);
  return copysize;
}

ssize_t CompCryptUtil::DecryptDecompressFile(CompCryptContext * ctx)
{
  return CryptUtil::crypt_file(ctx->cryptctx);
}

ssize_t CompCryptUtil::CompressEncryptFile(CompCryptContext * ctx)
{
  size_t const readbuffsize = ZSTD_CStreamInSize();
  void * readbuff = (void *)malloc(readbuffsize);

  size_t pressbuffsize = readbuffsize;
  void * pressbuff = (void *)malloc(pressbuffsize);

  size_t cryptbuffsize = readbuffsize;
  void * cryptbuff = (void *)malloc(cryptbuffsize + EVP_MAX_BLOCK_LENGTH);

  if(readbuff == NULL || pressbuff == NULL || cryptbuff == NULL){
    S3FS_PRN_ERR("Could not allocate buffer");
    return -1;
  }

  size_t totalread = 0, toread = readbuffsize;
  ssize_t readlen, presslen, cryptlen, writelen;

  for(;;){
    readlen = pread(ctx->infd, readbuff, toread, totalread);
    totalread += readlen;

    if(readlen == 0) break; //We have finished reading the input
    if(readlen == -1){
      S3FS_PRN_ERR("Error while reading from file (%d)", errno);
    }
    
    presslen = CompressUtil::do_compress(ctx->pressctx, readbuff, readlen, 
                                          &pressbuff, &pressbuffsize, &toread);

    if(toread > readbuffsize) toread = readbuffsize;

    if(presslen == -1){
      S3FS_PRN_ERR("Error while compressing");
      return -1;
    }else if(presslen > 0){ // We have some bytes to encrypt and write
      if(pressbuffsize > cryptbuffsize){ // We need to reallocate
        cryptbuffsize = pressbuffsize;
        void * temp = (void *)realloc(cryptbuff, cryptbuffsize + EVP_MAX_BLOCK_LENGTH);
        if(temp)
          cryptbuff = temp;
        else{
          S3FS_PRN_ERR("Error while reallocating");
          return -1;
        }
      }

      cryptlen = CryptUtil::do_crypt(ctx->cryptctx, pressbuff, presslen, cryptbuff);

      if(cryptlen == -1){
        S3FS_PRN_ERR("Error while encrypting");
        return -1;
      }

      writelen = pwrite(ctx->outfd, cryptbuff, cryptlen, ctx->bytes_written);
      ctx->bytes_written += writelen;

      if(writelen == -1){
        S3FS_PRN_ERR("Error writing to file");
        return -1;
      }
    }
  }
  
  if(!ctx->pressctx->finished){
    presslen = CompressUtil::do_compress(ctx->pressctx, NULL, 0, &pressbuff, &pressbuffsize, &toread);

    if(presslen == -1){
      S3FS_PRN_ERR("Error while compressing");
      return -1;
    }

    if(pressbuffsize > cryptbuffsize){
      cryptbuffsize = pressbuffsize;
      void * temp = (void *)realloc(cryptbuff, cryptbuffsize + EVP_MAX_BLOCK_LENGTH);
      if(temp)
        cryptbuff = temp;
      else{
        S3FS_PRN_ERR("Error while reallocating");
        return -1;
      }
    }

    cryptlen = CryptUtil::do_crypt(ctx->cryptctx, pressbuff, presslen, cryptbuff);

    if(cryptlen == -1){
      S3FS_PRN_ERR("Error while encrypting");
      return -1;
    }

    writelen = pwrite(ctx->outfd, cryptbuff, cryptlen, ctx->bytes_written);
    ctx->bytes_written += writelen; 

    if(writelen == -1){
      S3FS_PRN_ERR("Error writing to file");
      return -1;
    }
  }
 
  if(!ctx->cryptctx->finished){
    cryptlen = CryptUtil::do_crypt(ctx->cryptctx, NULL, 0, cryptbuff);

    if(cryptlen == -1){
      S3FS_PRN_ERR("Error while encrypting");
      return -1;
    }

    writelen = pwrite(ctx->outfd, cryptbuff, cryptlen, ctx->bytes_written);
    ctx->bytes_written += writelen; 

    if(writelen == -1){
      S3FS_PRN_ERR("Error writing to file");
      return -1;
    }
  }

  free(readbuff);
  free(pressbuff);
  free(cryptbuff);

  return ctx->bytes_written;
}
