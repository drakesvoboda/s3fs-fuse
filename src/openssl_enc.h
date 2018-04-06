#ifndef ENCRYPTIONUTILITY_H
#define ENCRYPTIONUTILITY_H

#include <openssl/evp.h>

class CryptContext {
public:
  EVP_CIPHER_CTX ctx;

  const unsigned char * salt;

  int fd;	// When uploading, read from this fd
			// When downloading, write to this fd

  ssize_t bytes_remaining;	// Keeps track of the number of bytes remaining to be read from fd
							// Or the number of bytes still to be downloaded
							// Can be -1 if the size is not known

  size_t bytes_finished;	// Used as offset for fd
							// Keeps track of the number of bytes read from fd
							// Or the number of bytes written to fd

  size_t paddedsize;	// Largest possible output size after encryption

  bool do_encrypt;		// Area we encrypting or decrypting?
  bool initialized;		// Have we initialized ctx?
  bool finished;		// Have we finished?

  CryptContext(int fd, size_t size, bool do_encrypt);  

  ~CryptContext() 
  {
    EVP_CIPHER_CTX_cleanup(&ctx);
  }
};


class CryptUtil {
friend class CryptContext;
private:
  const static size_t SALTSIZE = 8;
  const static size_t BUFFSIZE = (8 * 1024);
  const static bool IS_SALTED = false;
  const static char * pass;
  const static EVP_CIPHER * cipher;
  const static EVP_MD * digest;

public:
  /// Encrypts requested_size bytes from the file descriptor in ctx into buffer pointed to by ptr.
  /// Ensure that at least requested_size bytes have been allocated at ptr.
  /// Returns number of bytes written to ptr, updates ctx.
  /// return value must equal requested_size.
  static ssize_t do_crypt(CryptContext * ctx, const void * inbuff, size_t buffsize, void * outbuff);

  /// userp is a pointer to a CrpytContext object.
  static ssize_t DownloadEcryptedWriteCallback(void * ptr, size_t size, size_t nmemb, void * userp);
  static ssize_t CryptFile(int in_fd, int out_fd, bool do_encrypt);
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
