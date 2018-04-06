#ifndef ENCRYPTIONUTILITY_H
#define ENCRYPTIONUTILITY_H

#include <openssl/evp.h>

class CryptContext {
public:
    EVP_CIPHER_CTX ctx;
    bool initialized;
    const unsigned char * salt;
    int fd;
    size_t bytes_remaining; // Keeps track of the number of bytes remaining to be read from fd
    bool do_encrypt;
    size_t total_bytes_written; // Keeps track of the number of bytes that have been encrypted by the context

    size_t total_bytes_read; // Keeps track of the number of bytes read from fd
    size_t paddedsize; // Largest possible output size after encryption
    
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
    static size_t do_crypt(CryptContext * ctx, size_t requested_size, unsigned char * ptr, bool do_encrypt);

    /// userp is a pointer to a CrpytContext object.
    static size_t UploadEncryptedReadCallback(void * ptr, size_t size, size_t nmemb, void * userp);
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
