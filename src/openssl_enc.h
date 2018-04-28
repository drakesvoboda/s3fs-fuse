#ifndef ENCRYPTIONUTILITY_H
#define ENCRYPTIONUTILITY_H

#include <string>
#include <openssl/evp.h>

class CryptContext {
friend class CryptUtil;
private: 
  const static size_t SALTSIZE = 8;
  const static char * pass;
  const static EVP_CIPHER * cipher;
  const static EVP_MD * digest;
public:
  EVP_CIPHER_CTX * ctx;

  int infd, outfd;

  size_t bytes_written;

  bool do_encrypt;		// Area we encrypting or decrypting?
  bool initialized;		// Have we hashed a key and initialized ctx?
  bool finished;		// Have we finished?

  char * salt;
 
  CryptContext(int infd, int outfd, bool do_encrypt);  

  ~CryptContext() 
  {
	if(ctx)
	  EVP_CIPHER_CTX_free(ctx);

    if(this->salt)
      delete [] this->salt;
  }

  void setSalt(const char * salt);
  const char * getSalt() const;

  void init(); // Initializes the context with key and salt. 
			   // Must be executed before any bytes are encrypted by the context

  // Used by cUrl. Retrieves salt from header response. Initializes this context
  static size_t ParseSaltFromHeader(void * data, size_t blockSize, size_t numBlocks, void * userPtr);
};


class CryptUtil {
friend class CryptContext;
private:
public:
  static ssize_t do_crypt(CryptContext * ctx, const void * inbuff, size_t buffsize, void * outbuff);
  static ssize_t crypt_file(CryptContext * ctx); 
};
#endif

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
