#include <string.h>
#include <arpa/inet.h>
#include "rad_crypto.h"

#define AES_BLOCK_SIZE 16

void 
rad_calculate_md5(const void *content, unsigned int len, char * md_value)
{
  EVP_MD_CTX mdctx;
  
  EVP_DigestInit(&mdctx, EVP_md5());
  EVP_DigestUpdate(&mdctx, content, (size_t) len);
  EVP_DigestFinal(&mdctx, (unsigned char *) md_value, NULL);
}

void 
rad_calculate_sha1(const void *content, unsigned int len, char * md_value)
{
  EVP_MD_CTX mdctx;
  
  EVP_DigestInit(&mdctx, EVP_sha1());
  EVP_DigestUpdate(&mdctx, content, (size_t) len);
  EVP_DigestFinal(&mdctx, (unsigned char *) md_value, NULL);
}

void 
rad_calculate_hmac_md5(const void *content, unsigned int c_len, const char * key, int key_len, char * md_value, unsigned int md_len)
{
  HMAC_CTX mdctx;
  
  HMAC_CTX_init(&mdctx);
  HMAC_Init(&mdctx, key, key_len, EVP_md5());
#if 0
  if (HMAC_Update(&mdctx, content, c_len) == 0) {
    fprintf(stderr, "Error: cannot update HMAC-MD5\n");
    exit(1);
  }

  if (HMAC_Final(&mdctx, (unsigned char *) md_value, NULL) == 0) {
    fprintf(stderr, "Error: cannot finalize HMAC-MD5\n");
    exit(1);
  }
#else
  HMAC_Update(&mdctx, content, c_len);
  HMAC_Final(&mdctx, (unsigned char *) md_value, NULL);
#endif
  HMAC_CTX_cleanup(&mdctx);
}

void 
rad_calculate_hmac_sha1_128(const unsigned char * c1, unsigned int c1_len, 
			    const unsigned char * c2, unsigned int c2_len,
			    const char * key, int key_len, 
			    char * md_value)
{
  HMAC_CTX mdctx;
  unsigned char md_sha1[20];

  HMAC_CTX_init(&mdctx);
  HMAC_Init(&mdctx, key, key_len, EVP_sha1());
#if 0
  if (HMAC_Update(&mdctx, c1, c1_len) == 0) {
    fprintf(stderr, "Error: cannot update HMAC-SHA1\n");
    exit(1);
  }
  if (HMAC_Update(&mdctx, c2, c2_len) == 0) {
    fprintf(stderr, "Error: cannot update HMAC-SHA1\n");
    exit(1);
  }
  if (HMAC_Final(&mdctx, md_sha1, NULL) == 0) {
    fprintf(stderr, "Error: cannot finalize HMAC-SHA1\n");
    exit(1);
  }
#else
  HMAC_Update(&mdctx, c1, c1_len);
  HMAC_Update(&mdctx, c2, c2_len);
  HMAC_Final(&mdctx, md_sha1, NULL);
#endif

  HMAC_CTX_cleanup(&mdctx);
  memcpy(md_value, md_sha1, 16);
}

int 
rad_aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 1;
  unsigned char key[16], iv[16];
  
  /*
   * Gen key & IV for AES 128 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 16) {
    printf("Key size is %d bits - should be 128 bits\n", i * 8);
    return -1;
  }

  if (e_ctx) {
    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_128_cbc(), NULL, key, iv);
  }

  if (d_ctx) {
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_128_cbc(), NULL, key, iv);
  }

  return 0;
}

int
rad_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int p_len, unsigned char * ciphertext)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = p_len + AES_BLOCK_SIZE;
  int f_len = 0;

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, p_len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  return c_len + f_len;
}

/*
 * Decrypt *len bytes of ciphertext
 */
int
rad_aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int c_len, unsigned char * plaintext)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = c_len;
  int f_len = 0;
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, c_len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  return p_len + f_len;
}

void
rad_aes_release(EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
  if (e_ctx) {
    EVP_CIPHER_CTX_cleanup(e_ctx);
  }

  if (d_ctx) {
    EVP_CIPHER_CTX_cleanup(d_ctx);
  }
}

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} fr_SHA1_CTX;

typedef struct onesixty {
  unsigned char p[20];
} onesixty;

#define blk0(i) (block->l[i] = htonl(block->l[i]))

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */

#define blk0(i) (block->l[i] = htonl(block->l[i]))

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void fr_SHA1Transform(uint32_t state[5], const uint8_t buffer[64])
{
  uint32_t a, b, c, d, e;
  typedef union {
    uint8_t c[64];
    uint32_t l[16];
  } CHAR64LONG16;
  CHAR64LONG16 *block;
  uint8_t workspace[64];

    block = (CHAR64LONG16*)workspace;
    memcpy(block, buffer, 64);
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
}


/* fr_SHA1Init - Initialize new context */

void fr_SHA1Init(fr_SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void fr_SHA1Update(fr_SHA1_CTX* context, const uint8_t* data, unsigned int len)
{
unsigned int i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        fr_SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            fr_SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void fr_SHA1Final(uint8_t digest[20], fr_SHA1_CTX* context)
{
uint32_t i, j;
uint8_t finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    fr_SHA1Update(context, (const unsigned char *) "\200", 1);
    while ((context->count[0] & 504) != 448) {
        fr_SHA1Update(context, (const unsigned char *) "\0", 1);
    }
    fr_SHA1Update(context, finalcount, 8);  /* Should cause a fr_SHA1Transform() */
    for (i = 0; i < 20; i++) {
        digest[i] = (uint8_t)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
    /* Wipe variables */
    i = j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(&finalcount, 0, 8);
#ifdef SHA1HANDSOFF  /* make fr_SHA1Transform overwrite it's own static vars */
    fr_SHA1Transform(context->state, context->buffer);
#endif
}

void fr_SHA1FinalNoLen(uint8_t digest[20], fr_SHA1_CTX* context)
{
  uint32_t i, j;

    for (i = 0; i < 20; i++) {
        digest[i] = (uint8_t)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }

    /* Wipe variables */
    i = j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);

#ifdef SHA1HANDSOFF  /* make fr_SHA1Transform overwrite it's own static vars */
    fr_SHA1Transform(context->state, context->buffer);
#endif
}

static void onesixty_add_mod(onesixty *sum, onesixty *a, onesixty *b)
{
  unsigned long s;
  int i, carry;

  carry = 0;
  for(i=19; i>=0; i--) {
    s = a->p[i] + b->p[i] + carry;
    sum->p[i] = s & 0xff;
    carry = s >> 8;
  }
}

void fips186_2prf(uint8_t mk[20], uint8_t finalkey[160])
{
	fr_SHA1_CTX context;
	int j;
	onesixty xval, xkey, w_0, w_1, sum, one;
	uint8_t *f;
	uint8_t zeros[64];

	/*
	 * let XKEY := MK,
	 *
	 * Step 3: For j = 0 to 3 do
         *   a. XVAL = XKEY
         *   b. w_0 = SHA1(XVAL)
         *   c. XKEY = (1 + XKEY + w_0) mod 2^160
         *   d. XVAL = XKEY
         *   e. w_1 = SHA1(XVAL)
         *   f. XKEY = (1 + XKEY + w_1) mod 2^160
         * 3.3 x_j = w_0|w_1
	 *
	 */
	memcpy(&xkey, mk, sizeof(xkey));

	/* make the value 1 */
	memset(&one,  0, sizeof(one));
	one.p[19]=1;

	f=finalkey;

	for(j=0; j<4; j++) {
		/*   a. XVAL = XKEY  */
		xval = xkey;

		/*   b. w_0 = SHA1(XVAL)  */
		fr_SHA1Init(&context);

		memset(zeros, 0, sizeof(zeros));
		memcpy(zeros, xval.p, 20);
#ifndef WITH_OPENSSL_SHA1
		fr_SHA1Transform(context.state, zeros);
#else
		fr_SHA1Transform(&context, zeros);
#endif
		fr_SHA1FinalNoLen(w_0.p, &context);

		/*   c. XKEY = (1 + XKEY + w_0) mod 2^160 */
		onesixty_add_mod(&sum,  &xkey, &w_0);
		onesixty_add_mod(&xkey, &sum,  &one);

		/*   d. XVAL = XKEY  */
		xval = xkey;

		/*   e. w_1 = SHA1(XVAL)  */
		fr_SHA1Init(&context);

		memset(zeros, 0, sizeof(zeros));
		memcpy(zeros, xval.p, 20);
#ifndef WITH_OPENSSL_SHA1
		fr_SHA1Transform(context.state, zeros);
#else
		fr_SHA1Transform(&context, zeros);
#endif
		fr_SHA1FinalNoLen(w_1.p, &context);

		/*   f. XKEY = (1 + XKEY + w_1) mod 2^160 */
		onesixty_add_mod(&sum,  &xkey, &w_1);
		onesixty_add_mod(&xkey, &sum,  &one);

		/* now store it away */
		memcpy(f, &w_0, 20);
		f += 20;

		memcpy(f, &w_1, 20);
		f += 20;
	}
}

void
rad_calculate_eap_sim_keys(char * master_key, char * K_aut, char * K_encr, char * msk, char * emsk)
{
  unsigned char fk[160];

  fips186_2prf((unsigned char *) master_key, fk);

  /* split up the result */
  memcpy(K_encr, fk +  0, 16);    /* 128 bits for encryption    */
  memcpy(K_aut,  fk + 16, 16);    /* 128 bits for auth */
  memcpy(msk,    fk + 32, 64);    /* 64 bytes for Master Session Key */
  memcpy(emsk,   fk + 96, 64);    /* 64- extended Master Session Key */
}

