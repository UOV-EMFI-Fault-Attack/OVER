// SPDX-License-Identifier: CC0 OR Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

//#include "benchmark.h"

#if defined(_VALGRIND_)
#define TEST_GENKEY 2
#define TEST_RUN 5
#else
#define TEST_GENKEY 50
#define TEST_RUN 500
#endif



int main(void) {
    printf("%s\n", OV_ALGNAME );
    printf("sk size: %d\n", CRYPTO_SECRETKEYBYTES );
    printf("pk size: %d\n", CRYPTO_PUBLICKEYBYTES );
    printf("signature overhead: %d\n\n", CRYPTO_BYTES );


    unsigned char *pk = (unsigned char *)malloc( CRYPTO_PUBLICKEYBYTES );
    unsigned char *sk = (unsigned char *)malloc( CRYPTO_SECRETKEYBYTES );

    int ret = 0;
    int r0;
    r0 = crypto_sign_keypair( pk, sk);
    if ( 0 != r0 ) {
        printf("generating key return %d.\n", r0);
        ret = -1;
        goto clean_exit;
    }

    FILE *sk_f = fopen("../keys/sk.h", "w");
    if (!sk_f) {
        printf("Failed to open file for writing.\n");
        ret = -1;
        goto clean_exit;
    }

    fprintf(sk_f, "#ifndef SK_H\n#define SK_H\n\n");
    fprintf(sk_f, "const unsigned char sk_comp[%d] = {", CRYPTO_SECRETKEYBYTES);
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        fprintf(sk_f, "0x%02X%s", sk[i], (i < CRYPTO_SECRETKEYBYTES - 1) ? ", " : "");
    }
    fprintf(sk_f, "};\n\n#endif // SK_H\n");

    fclose(sk_f);

    FILE *pk_f = fopen("../keys/pk.h", "w");
    if (!pk_f) {
        printf("Failed to open file for writing.\n");
        ret = -1;
        goto clean_exit;
    }
    fprintf(pk_f, "#ifndef PK_H\n#define PK_H\n\n");
    fprintf(pk_f, "const unsigned char pk_comp[%d] = {", CRYPTO_PUBLICKEYBYTES);
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        fprintf(pk_f, "0x%02X%s", pk[i], (i < CRYPTO_PUBLICKEYBYTES - 1) ? ", " : "");
    }
    fprintf(pk_f, "};\n\n#endif // PK_H\n");

    fclose(pk_f);
    

    printf("Secret key and public key written to key directory\n");



clean_exit:
    free( pk );
    free( sk );
    return ret;
}

