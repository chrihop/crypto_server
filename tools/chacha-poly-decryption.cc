#include <crypto/enclave.h>
#include <cstdio>
using namespace std;

struct crypto_sc_mac_context_t ctx;

uint8_t key_b64[96];
uint8_t key[32];
uint8_t cypher_raw[1024];
uint8_t cypher[1024];
uint8_t tag_raw[128];
uint8_t msg[1024];

void hex_read(uint8_t* dst, const char* src, size_t len)
{
    for (size_t i = 0; i < len; i+= 3)
    {
        dst[i/3] = strtol(&src[i], NULL, 16);
    }
}

int main()
{
    size_t len;
    crypto_init();
    do {
        printf("Secrete Key: ");

        fgets((char*)key_b64, 96, stdin);
        len = strnlen((const char *) key_b64, 96);
    } while (crypto_b64_decode(key, 32, &len, key_b64, len) != 0
        || len != 32);
    crypto_sc_mac_init(&ctx, key, 32, 0);

    while (true)
    {
        printf("Encrypted Data: ");
        fgets((char*)cypher_raw, 1024, stdin);
        len = strnlen((const char *) cypher_raw, 1024);
        hex_read(cypher, (const char *) cypher_raw, len);

        size_t cypher_len = len / 3;
        printf("Tag: ");
        fgets((char*)tag_raw, 128, stdin);
        len = strnlen((const char *) tag_raw, 128);
        hex_read(cypher + cypher_len, (const char *) tag_raw, len);

        int succ = crypto_sc_mac_decrypt(&ctx, cypher, cypher_len + len / 3, msg, &len);
        if (!succ)
        {
            printf("message is tampered!\n");
            continue ;
        }

        printf("Decrypted Data: %s\n", msg);
    }
    return 0;
}
