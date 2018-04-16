#ifndef ENCRYPTIONUTILITY_H
#define ENCRYPTIONUTILITY_H

#include <openssl/evp.h>

class CryptContext {
friend class CryptUtil;
private: 
  const static size_t SALTSIZE = 8;
  const static bool IS_SALTED = false;
  const static char * pass;
  const static EVP_CIPHER * cipher;
  const static EVP_MD * digest;
public:
  EVP_CIPHER_CTX * ctx;

  int infd;	// When uploading, read from this fd

  ssize_t bytes_remaining;	// Keeps track of the number of bytes remaining to be read from fd
							// Or the number of bytes still to be downloaded
							// Can be -1 if the size is not known

  size_t bytes_finished;	// Keeps track of the number of bytes output by the context 

  size_t paddedsize;	// Largest possible output size after encryption (0 bytes padding in our case)

  int outfd; // When downloading, write to this fd

  bool finished;		// Have we finished?
  bool do_encrypt;		// Area we encrypting or decrypting?
  bool initialized;		// Have we hashed a key and initialized ctx?

  char salt[CryptContext::SALTSIZE + 1];
  unsigned char key[16];
 
  CryptContext(int infd, size_t insize, int outfd, bool do_encrypt);  

  ~CryptContext() 
  {
	if(this->ctx && this->initialized){
      EVP_CIPHER_CTX_free(ctx);
	}
  }

  void setSalt(const char * salt);

  void init(); // Initializes the context with key and salt. 
			   // Must be executed before any bytes are encrypted by the context

  static size_t ParseSaltFromHeader(void * data, size_t blockSize, size_t numBlocks, void * userPtr);
};


class CryptUtil {
friend class CryptContext;
private:

public:
  /// Encrypts requested_size bytes from the file descriptor in ctx into buffer pointed to by ptr.
  /// Ensure that at least requested_size bytes have been allocated at ptr.
  /// Returns number of bytes written to ptr, updates ctx.
  /// return value must equal requested_size.
  static ssize_t do_crypt(CryptContext * ctx, const void * inbuff, size_t buffsize, void * outbuff);

  /// userp is a pointer to a CrpytContext object.
  static ssize_t DownloadEcryptedWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp);
  static ssize_t CryptFile(CryptContext * ctx);
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
