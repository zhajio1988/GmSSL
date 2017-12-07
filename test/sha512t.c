/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

static const unsigned char app_c1[SHA512_DIGEST_LENGTH] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};

static const unsigned char app_c2[SHA512_DIGEST_LENGTH] = {
    0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
    0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
    0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
    0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
    0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
    0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
    0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
    0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09
};

static const unsigned char app_c3[SHA512_DIGEST_LENGTH] = {
    0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64,
    0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
    0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28,
    0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
    0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a,
    0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
    0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
    0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b
};

static const unsigned char app_d1[SHA384_DIGEST_LENGTH] = {
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
    0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
    0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
    0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
    0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
    0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
};

static const unsigned char app_d2[SHA384_DIGEST_LENGTH] = {
    0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8,
    0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b, 0x47,
    0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2,
    0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12,
    0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9,
    0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39
};

static const unsigned char app_d3[SHA384_DIGEST_LENGTH] = {
    0x9d, 0x0e, 0x18, 0x09, 0x71, 0x64, 0x74, 0xcb,
    0x08, 0x6e, 0x83, 0x4e, 0x31, 0x0a, 0x4a, 0x1c,
    0xed, 0x14, 0x9e, 0x9c, 0x00, 0xf2, 0x48, 0x52,
    0x79, 0x72, 0xce, 0xc5, 0x70, 0x4c, 0x2a, 0x5b,
    0x07, 0xb8, 0xb3, 0xdc, 0x38, 0xec, 0xc4, 0xeb,
    0xae, 0x97, 0xdd, 0xd8, 0x7f, 0x3d, 0x89, 0x85
};

static const unsigned char app_e1[SHA512T224_DIGEST_LENGTH] = {
    0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54, 
    0xda, 0xae, 0x75, 0x30, 0x46, 0x08, 0x42, 0xe2, 
    0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4, 
    0x3e, 0x89, 0x24, 0xaa  
};

static const unsigned char app_e2[SHA512T224_DIGEST_LENGTH] = {
    0x23, 0xfe, 0xc5, 0xbb, 0x94, 0xd6, 0x0b, 0x23, 
    0x30, 0x81, 0x92, 0x64, 0x0b, 0x0c, 0x45, 0x33, 
    0x35, 0xd6, 0x64, 0x73, 0x4f, 0xe4, 0x0e, 0x72, 
    0x68, 0x67, 0x4a, 0xf9
};

static const unsigned char app_f1[SHA512T256_DIGEST_LENGTH] = {
    0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 
    0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab, 
    0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46, 
    0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23
};

static const unsigned char app_f2[SHA512T256_DIGEST_LENGTH] = {
    0x39, 0x28, 0xe1, 0x84, 0xfb, 0x86, 0x90, 0xf8, 
    0x40, 0xda, 0x39, 0x88, 0x12, 0x1d, 0x31, 0xbe, 
    0x65, 0xcb, 0x9d, 0x3e, 0xf8, 0x3e, 0xe6, 0x14, 
    0x6f, 0xea, 0xc8, 0x61, 0xe1, 0x9b, 0x56, 0x3a
};



int main(int argc, char **argv)
{
    unsigned char md[SHA512_DIGEST_LENGTH];
    int i;
    EVP_MD_CTX *evp;

    fprintf(stdout, "Testing SHA-512 ");

    if (!EVP_Digest("abc", 3, md, NULL, EVP_sha512(), NULL))
        goto err;
    if (memcmp(md, app_c1, sizeof(app_c1))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 1 of 3 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    if (!EVP_Digest("abcdefgh" "bcdefghi" "cdefghij" "defghijk"
                    "efghijkl" "fghijklm" "ghijklmn" "hijklmno"
                    "ijklmnop" "jklmnopq" "klmnopqr" "lmnopqrs"
                    "mnopqrst" "nopqrstu", 112, md, NULL, EVP_sha512(), NULL))
        goto err;
    if (memcmp(md, app_c2, sizeof(app_c2))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 2 of 3 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    evp = EVP_MD_CTX_new();
    if (evp == NULL) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 3 of 3 failed. (malloc failure)\n");
        return 1;
    }
    if (!EVP_DigestInit_ex(evp, EVP_sha512(), NULL))
        goto err;
    for (i = 0; i < 1000000; i += 288) {
        if (!EVP_DigestUpdate(evp, "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa",
                              (1000000 - i) < 288 ? 1000000 - i : 288))
            goto err;
    }
    if (!EVP_DigestFinal_ex(evp, md, NULL))
            goto err;
    EVP_MD_CTX_reset(evp);

    if (memcmp(md, app_c3, sizeof(app_c3))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 3 of 3 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    fprintf(stdout, " passed.\n");
    fflush(stdout);

    fprintf(stdout, "Testing SHA-384 ");

    if (!EVP_Digest("abc", 3, md, NULL, EVP_sha384(), NULL))
        goto err;
    if (memcmp(md, app_d1, sizeof(app_d1))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 1 of 3 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    if (!EVP_Digest("abcdefgh" "bcdefghi" "cdefghij" "defghijk"
                    "efghijkl" "fghijklm" "ghijklmn" "hijklmno"
                    "ijklmnop" "jklmnopq" "klmnopqr" "lmnopqrs"
                    "mnopqrst" "nopqrstu", 112, md, NULL, EVP_sha384(), NULL))
        goto err;
    if (memcmp(md, app_d2, sizeof(app_d2))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 2 of 3 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    if (!EVP_DigestInit_ex(evp, EVP_sha384(), NULL))
        goto err;
    for (i = 0; i < 1000000; i += 64) {
        if (!EVP_DigestUpdate(evp, "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa"
                              "aaaaaaaa" "aaaaaaaa" "aaaaaaaa" "aaaaaaaa",
                              (1000000 - i) < 64 ? 1000000 - i : 64))
            goto err;
    }
    if (!EVP_DigestFinal_ex(evp, md, NULL))
        goto err;
    EVP_MD_CTX_free(evp);

    if (memcmp(md, app_d3, sizeof(app_d3))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 3 of 3 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    fprintf(stdout, "Testing SHA-512t224 ");
    printf("Testing SHA-512t224\n");

    if (!EVP_Digest("abc", 3, md, NULL, EVP_sha512t224(), NULL))
        goto err;
    if (memcmp(md, app_e1, sizeof(app_e1))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 1 of 2 failed.\n");
        printf("\nTEST 1 of 2 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    if (!EVP_Digest("abcdefgh" "bcdefghi" "cdefghij" "defghijk"
                    "efghijkl" "fghijklm" "ghijklmn" "hijklmno"
                    "ijklmnop" "jklmnopq" "klmnopqr" "lmnopqrs"
                    "mnopqrst" "nopqrstu", 112, md, NULL, EVP_sha512t224(), NULL))
        goto err;
    if (memcmp(md, app_e2, sizeof(app_e2))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 2 of 2 failed.\n");
        printf("\nTEST 2 of 2 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    fprintf(stdout, "Testing SHA-512t256 ");

    if (!EVP_Digest("abc", 3, md, NULL, EVP_sha512t256(), NULL))
        goto err;
    if (memcmp(md, app_f1, sizeof(app_f1))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 1 of 2 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);

    if (!EVP_Digest("abcdefgh" "bcdefghi" "cdefghij" "defghijk"
                    "efghijkl" "fghijklm" "ghijklmn" "hijklmno"
                    "ijklmnop" "jklmnopq" "klmnopqr" "lmnopqrs"
                    "mnopqrst" "nopqrstu", 112, md, NULL, EVP_sha512t256(), NULL))
        goto err;
    if (memcmp(md, app_f2, sizeof(app_f2))) {
        fflush(stdout);
        fprintf(stderr, "\nTEST 2 of 2 failed.\n");
        return 1;
    } else
        fprintf(stdout, ".");
    fflush(stdout);    

    fprintf(stdout, " passed.\n");
    fflush(stdout);

    return 0;

 err:
    fflush(stdout);
    fprintf(stderr, "\nFatal EVP error!\n");
    return 1;
}
