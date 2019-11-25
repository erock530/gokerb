#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "crypto_int.h"
#include "k5-int.h"
#include "krb5.h"

static krb5_context kctx;

#define CHARS_TO_COPY 4
int genParamString(int n, int strLen, unsigned char* a) {

    if(strLen != CHARS_TO_COPY) {
        return -1;
    }

    a[3] = n & 0xff;
    a[2] = (n>>8)  & 0xff;
    a[1] = (n>>16) & 0xff;
    a[0] = (n>>24) & 0xff;

    return 0;
}

char* allocChar(char* str, uint len) {
    int i = 0;
    char *c = malloc( sizeof(char) * ( len + 1 ) );

    for (i=0; i<len; ++i) {
        c[i] = str[i];
    }

    return c;
}

krb5_octet* bytesToOctet(char* str, uint len) {
    int i = 0;
    krb5_octet *c = malloc( sizeof(krb5_octet) * ( len + 1 ) );

    for (i=0; i<len; ++i) {
        c[i] = str[i];
    }

    return c;
}

krb5_context getKrb5Context() {
    krb5_error_code code = 0;

    if (kctx == NULL || kctx->magic == 0) {
        printf("initializing krb5_context\n");
        code = krb5_init_context(&kctx);
        if (code) {
            printf("error while initializing Kerberos 5 library: %d", code);
            return NULL;
        }
    }

    return kctx;
}

void freeKrb5Context() {
    if (kctx != NULL)
        krb5_free_context(kctx);
}
