#include <openssl/rsa.h>
#include <openssl/pem.h>
 
int main(){
	const int kBits = 2048;
	unsigned long e = RSA_F4;
	int keylen;
	char *pem_key;
	
	// BIGNUM PART
	BIGNUM* bignum = BN_new();
	if(BN_set_word(bignum, e))
		printf("[Debug] BIGNUM allocated!\n");
	else
		printf("[Debug] BIGNUM NOT allocated!\n");
 
	// RSA PART
	RSA *rsa = RSA_new();
	if(RSA_generate_key_ex(rsa, 2048, bignum, NULL))
		printf("[Debug] RSA allocated!\n");
	else
		printf("[Debug] RSA NOT allocated!\n");
 
	// BIO PART
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
 
	keylen = BIO_pending(bio);
	pem_key = calloc(keylen+1, 1); /* Null-terminate */
	BIO_read(bio, pem_key, keylen);
 
	// OUTPUT
	printf("%s", pem_key);
 
	// FREE THE MEMORY
	BIO_free_all(bio);
	RSA_free(rsa);
	BN_free(bignum);
	free(pem_key);
	return 0;
}