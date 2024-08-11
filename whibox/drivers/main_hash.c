#include <stdio.h>
#include <stdint.h>

void ECDSA_256_sign(uint8_t *sig, const uint8_t *hash);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hash>\n", argv[0]);
        return 1;
    }

    const char *hash_input = argv[1];
    uint8_t hash[32]={0};

    for (int i = 0; i < 32; i++) {
        sscanf(&hash_input[i * 2], "%2hhx", &hash[i]);
    }

    uint8_t sig[64];

    ECDSA_256_sign(sig, hash);
    for (int i = 0; i < 64; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");

    return 0;
}
