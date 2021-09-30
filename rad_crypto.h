#ifndef __RAD_CRYPTO_H
#define __RAD_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/hmac.h>

void rad_calculate_md5(const void *content, unsigned int c_len, char * md_value);
void rad_calculate_sha1(const void *content, unsigned int c_len, char * md_value);
void rad_calculate_hmac_md5(const void *content, unsigned int c_len, const char * key, int key_len, char * md_value, unsigned int md_len);
void rad_calculate_hmac_sha1_128(const unsigned char *c1, unsigned int c1_len, 
				 const unsigned char * c2, unsigned int c2_len, 
				 const char * key, int key_len, 
				 char * md_value);
int  rad_aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
int  rad_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int p_len, unsigned char * cipheertext);
int  rad_aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int c_len, unsigned char * plaintext);
void rad_aes_release(EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
void rad_calculate_eap_sim_keys(char * master_key, char * K_aut, char * K_encr, char * msk, char * emsk);

#endif
