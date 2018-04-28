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

#include "common.h"
#include "openssl_enc.h"
#include "string_util.h"

// Set Statics
const char * CryptContext::pass = "key";
const EVP_CIPHER * CryptContext::cipher = EVP_rc4();
const EVP_MD * CryptContext::digest = EVP_md5();

ssize_t CryptUtil::crypt_file(CryptContext * ctx)
{
  ssize_t cryptlen;
  ssize_t readlen, totalread = 0, writelen;

  size_t buffsize = 16 * 1024;

  unsigned char inbuff[buffsize];
  unsigned char outbuff[buffsize + EVP_MAX_BLOCK_LENGTH];

  for(;;totalread += readlen, ctx->bytes_written += writelen){
	readlen = pread(ctx->infd, (void *)inbuff, buffsize, totalread);

	if(readlen == 0) break;
	else if(readlen == -1){
	  S3FS_PRN_ERR("Error reading from file(%d)", errno); 
	  return -1;
	}
	
	cryptlen = CryptUtil::do_crypt(ctx, (const void *)inbuff, readlen, (void *)outbuff);

	if (cryptlen == 0) break;
	else if (cryptlen == -1){
	  S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
	}

	writelen = pwrite(ctx->outfd, (const void *)outbuff, cryptlen, ctx->bytes_written);
	
	if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
	}
  }

  if(!ctx->finished){
    cryptlen = CryptUtil::do_crypt(ctx, inbuff, 0, outbuff); // Finish crypt

    if (cryptlen == -1){
      S3FS_PRN_ERR("Error during crypt(%d)", errno); 
	  return -1;
    }
  
    writelen = pwrite(ctx->outfd, (const void *)outbuff, cryptlen, ctx->bytes_written);
	
    if(writelen == -1){
	  S3FS_PRN_ERR("Error writing to file(%d)", errno); 
	  return -1;
    }

    ctx->bytes_written += writelen;
  }

  S3FS_PRN_INFO("[returning: %ld]", ctx->bytes_written);

  return ctx->bytes_written;
}

ssize_t CryptUtil::do_crypt(CryptContext * ctx, const void * inputbuff, size_t buffsize, void * outputbuff)
{
  unsigned char * inbuff = (unsigned char *)inputbuff;
  unsigned char * outbuff = (unsigned char *)outputbuff;

  if(!ctx->initialized){
    S3FS_PRN_ERR("This encryption context has not been initialized");
	return -1;
  }else if(ctx->finished){
    S3FS_PRN_INFO("This encryption context has already finished");
	return 0;
  }

  int writelen = 0;

  if(buffsize > 0){
	if(EVP_CipherUpdate(ctx->ctx, outbuff, &writelen, inbuff, buffsize) == 0){
      S3FS_PRN_ERR("Error while encrypting/decrypting(%d)", errno);
      return -1;
	}
  }else if(buffsize == 0){	
	if(EVP_CipherFinal(ctx->ctx, outbuff, &writelen) == 0){
      S3FS_PRN_ERR("Error while encrypting/decrypting(%d)", errno);
      return -1;
	}

    ctx->finished = true;
  }

  S3FS_PRN_INFO("[requested: %ld][returning: %d]", buffsize, writelen);
  return writelen;
}

CryptContext::CryptContext(int infd, int outfd, bool do_encrypt): 
  ctx(EVP_CIPHER_CTX_new()),
  infd(infd), outfd(outfd),
  bytes_written(0),
  do_encrypt(do_encrypt),
  initialized(false),
  finished(false),
  salt(NULL)
{
  char saltbuff[CryptContext::SALTSIZE + 1]; 

  if(do_encrypt){ //If we are encrypting, generate random salt
    if(RAND_bytes((unsigned char *)saltbuff, CryptContext::SALTSIZE) == 0){
      S3FS_PRN_ERR("Failed to randomly generate encryption salt");
	}

	saltbuff[CryptContext::SALTSIZE] = '\0';
	setSalt(saltbuff);
  }
}

const char * CryptContext::getSalt() const{
  static const char * nullret = "";
  if(!salt)
	return nullret;
  return salt;
}

void CryptContext::setSalt(const char * salt){
  if(this->salt)
    delete [] this->salt;
  
  this->salt = new char[strlen(salt)+1];
  strcpy(this->salt, salt);
}

void CryptContext::init()
{
  unsigned char key[16], iv[EVP_MAX_IV_LENGTH];

  if(PKCS5_PBKDF2_HMAC(CryptContext::pass, strlen(CryptContext::pass), (unsigned char *)this->salt, strlen(this->salt), 1, CryptContext::digest, 16, key) == 0)
    S3FS_PRN_ERR("Failed to generate key");

  if(0 == EVP_CipherInit(this->ctx, CryptContext::cipher, key, iv, this->do_encrypt)){
    S3FS_PRN_ERR("Failed to initalize crypt context");
	return;
  }

  this->initialized = true;
}

// For decryption on download. 
// Used by cUrl to retrieve salt bytes from header response. 
// Sets salt and initalizes context
size_t CryptContext::ParseSaltFromHeader(void * data, size_t blockSize, size_t numBlocks, void * userPtr){
  CryptContext * ctx = reinterpret_cast<CryptContext*>(userPtr);
  if(!ctx->initialized){
    std::string header(reinterpret_cast<char*>(data), blockSize * numBlocks);
    std::string key;
    std::stringstream ss(header);
    if(getline(ss, key, ':')){
      std::string lkey = key;
      std::transform(lkey.begin(), lkey.end(), lkey.begin(), static_cast<int (*)(int)>(std::tolower));
      if(lkey.compare(0,15,"x-amz-meta-salt") == 0){
        std::string value;
        getline(ss, value);
		size_t plen;
        unsigned char * salt = s3fs_decode64((const char *)trim(value).c_str(), &plen);
	    ctx->setSalt((const char *)salt);
	    ctx->init();
      }
    }
  }
  return blockSize * numBlocks;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
