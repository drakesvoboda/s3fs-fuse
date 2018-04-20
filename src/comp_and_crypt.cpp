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

ssize_t CompCryptUtil::ProcessFile(CompCryptContext * ctx)
{
  ssize_t cryptlen;
  ssize_t readlen, totalread = 0, writelen, totalwrite = 0;

  size_t buffsize = 16 * 1024;

  unsigned char inbuff[buffsize];
  unsigned char outbuff[buffsize + EVP_MAX_BLOCK_LENGTH];

  for(;;totalread += readlen, totalwrite += writelen){
	readlen = pread(ctx->infd, (void *)inbuff, buffsize, totalread);

	if(readlen == 0) break;
	else if(readlen == -1){
	  S3FS_PRN_ERR("Error reading from file(%d)", errno); 
	  return -1;
	}
	
	cryptlen = CryptUtil::do_crypt(ctx->cryptctx, (const void *)inbuff, readlen, (void *)outbuff);

	if (cryptlen == 0) break;
	else if (cryptlen == -1){
	  S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
	}

	writelen = pwrite(ctx->outfd, (const void *)outbuff, cryptlen, totalwrite);
	
	if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
	}
  }

  if(!ctx->cryptctx->finished){
    cryptlen = CryptUtil::do_crypt(ctx->cryptctx, inbuff, 0, outbuff); // Finish crypt

    if (cryptlen == -1){
      S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
    }
  
    writelen = pwrite(ctx->outfd, (const void *)outbuff, cryptlen, totalwrite);
	
    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
    }

    totalwrite += writelen;
  }

  S3FS_PRN_INFO("[returning: %ld]", totalwrite);

  return totalwrite;
}
