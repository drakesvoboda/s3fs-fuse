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
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <list>
#include <vector>

#include "common.h"
#include "openssl_enc.h"
#include "curl.h"

//Set Statics
const char * CryptUtil::pass = "key";
const EVP_CIPHER * CryptUtil::cipher = EVP_rc4();
const EVP_MD * CryptUtil::digest = EVP_md5();

size_t CryptUtil::DownloadEcryptedWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp)
{
  CryptContext * ctx = reinterpret_cast<CryptContext*>(userp);

  size_t requested_size = size * nmemb;
  S3FS_PRN_INFO("[requested: %ld][remaining: %ld]", requested_size, ctx->bytes_remaining);

  size_t copysize = (requested_size < ctx->bytes_remaining) ? requested_size : ctx->bytes_remaining;
  size_t ret;

  if(requested_size < 1 || ctx->fd == -1 || ctx->bytes_remaining < 1)
	ret =  0;
  else	
	ret = CryptUtil::do_crypt(ctx, copysize, (unsigned char*)ptr);

  S3FS_PRN_INFO("[requested: %ld][given: %ld]", requested_size, ret);
  S3FS_PRN_INFO("[text: %s]", (char *)ptr);

  return ret;
}

ssize_t CryptUtil::CryptFile(int in_fd, size_t in_file_size, int out_fd, bool do_encrypt)
{
  S3FS_PRN_INFO("[in_fd: %d][in_file_size: %ld][out_fd: %d]", in_fd, in_file_size, out_fd);

  CryptContext * ctx = new CryptContext(in_fd, in_file_size, do_encrypt);

  size_t cryptlen;
  ssize_t writelen, totalwrite = 0;

  unsigned char buffer[16 * 1024];

  for(;ctx->bytes_remaining > 0 && !ctx->finished; totalwrite += writelen){
	cryptlen = do_crypt(ctx, 16 * 1024, buffer);
	if (cryptlen == 0) break;
	writelen = pwrite(out_fd, (const void *)buffer, cryptlen, totalwrite);
	if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
	}
  }

  delete ctx;

  return totalwrite;
}

size_t CryptUtil::do_crypt(CryptContext * ctx, size_t requested_size, unsigned char * ptr)
{
  unsigned char * inbuff = new unsigned char[requested_size]; //Buffer to store between read and crypt
  int readlen = 0, writelen = 0;
  size_t totalwrite = 0, totalread = 0;

  for(;totalwrite < requested_size; totalwrite += writelen, totalread += readlen, ctx->bytes_finished += readlen){
    //This loop should only run once. The first chunk read and encrypted should be requested_size bytes long
	readlen = pread(ctx->fd, inbuff, requested_size - totalread, ctx->bytes_finished);

    if(readlen == -1){
      S3FS_PRN_ERR("Error reading from file(%d)", errno); 
      return 0;
	}
	else if(readlen == 0) 
      break; //We've finished reading from the file (only cipher padding should be left)
	
	if(EVP_CipherUpdate(&(ctx->ctx), &(ptr)[totalwrite], &writelen, inbuff, readlen) == 0){
      S3FS_PRN_ERR("Error while encrypting/decrypting(%d)", errno);
      return 0;
	}
  }

  ctx->bytes_remaining -= totalread;

  if(ctx->bytes_remaining < 1 && !ctx->finished){	//We have finished reading from the file. Only cipher padding remains.
	//This should add 0 bytes since RC4 is a stream cipher
	if(EVP_CipherFinal_ex(&(ctx->ctx), &(ptr)[totalwrite], &writelen) == 0){
      S3FS_PRN_ERR("Error while encrypting/decrypting(%d)", errno);
      return 0;
	}

    ctx->finished = true;

	totalwrite += writelen;
  }

  delete inbuff;

  return totalwrite;
}

CryptContext::CryptContext(int fd, size_t size, bool do_encrypt): 
  fd(fd), 
  bytes_remaining(size), 
  bytes_finished(0), 
  paddedsize(size),
  do_encrypt(do_encrypt)
{
  unsigned char key[16], iv[EVP_MAX_IV_LENGTH];
  int saltlen = 0;
  salt = NULL;

  if(PKCS5_PBKDF2_HMAC(CryptUtil::pass, strlen(CryptUtil::pass), salt, saltlen, 1, CryptUtil::digest, 16, key) == 0)
    S3FS_PRN_ERR("Failed to generate key");

  EVP_CIPHER_CTX_init(&ctx);
  EVP_CipherInit_ex(&ctx, CryptUtil::cipher, NULL, key, iv, do_encrypt);
  initialized = true;
  finished = bytes_remaining < 1;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
