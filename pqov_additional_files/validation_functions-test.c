#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "pk.h"
#include "sk.h"

#include "utils_prng.h"
#include "utils_hash.h"
#include "utils_malloc.h"


int verify_signature(unsigned char *m,unsigned char *sm, size_t smlen){
    unsigned long long mlen = 256;
    if (sm == NULL || smlen == 0) {
        fprintf(stderr, "Invalid input: sm is NULL or smlen is 0\n");
        return -1;
    }
    if (m == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    int ret = crypto_sign_open(m, &mlen, sm, smlen, pk_comp);
    if (ret != 0) {
        return 1;
    }
    return 0;
}

int generate_faulted_sig(unsigned char *m, unsigned char *sm, unsigned char *salt, unsigned char *out) {
    unsigned long long smlen;
    unsigned long long mlen = 256;
    const unsigned char *sk = sk_comp;

    unsigned char *sig = sm + mlen;
    // If salt is passed, use that for signature generation, else use a random generated one
    if (salt != NULL) {
        memcpy(sig + _PUB_N_BYTE, salt, _SALT_BYTE);
    } else {
        randombytes(sig + _PUB_N_BYTE, _SALT_BYTE);
    }

    // Generate new signature with the extracted message
    int ret = crypto_sign(sm, &smlen, m, mlen, sk);
    if (ret != 0)
    {
        fprintf(stderr, "crypto_sign() return %d.\n", ret);
        return -1;
    }

    // The attacked memcpy is commented out in pqov code, so the oil can be read from the signature
    memcpy(out, sm + mlen, OV_SIGNATUREBYTES);
    return 0;
}

int main(void)
{
}
