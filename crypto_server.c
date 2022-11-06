#include <crypto/enclave.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdatomic.h>
#include <threads.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>



struct enclave_key_store_t    root_key;
struct crypto_ds_public_key_t device_pubkey;
uint8_t                       device_fingerprint[32];
uint8_t                       device_fingerprint_b64[96];
crypto_hash_context_t         hash;

struct tcp_socket_t
{
    int fd;
    bool terminate;
};

struct tcp_socket_t server;

struct worker_t
{
    thrd_t                         thread;
    struct sockaddr_in             client_address;
    socklen_t                      client_address_len;
    int                            connection;
    uint8_t                        secrete_key[32];
    struct crypto_sc_mac_context_t cypher;
    uint8_t                        buffer[1024];
    uint8_t                        output[1024 + 32];
    uint8_t                        tag_b64[48];
    size_t                         output_len;
};

static char secret_key_b64[96];

static int
crypto_worker(void* arg)
{
    struct worker_t *me = (struct worker_t*)arg;
    if (me == NULL)
    {
        return -1;
    }

    while (! server.terminate)
    {
        if (me->connection == -1)
        {
            return 0;
        }

        ssize_t len = recv(me->connection, me->buffer, 1024, 0);
        if (len == -1 || len == 0)
        {
            close(me->connection);
            me->connection = -1;
            printf("client %s:%d disconnected!\n", inet_ntoa(me->client_address.sin_addr), ntohs(me->client_address.sin_port));
            return -1;
        }
        crypto_sc_mac_encrypt(&me->cypher, me->buffer, len, me->output, &me->output_len);
        size_t tag_len;
        crypto_b64_encode(me->tag_b64, 48, &tag_len, me->output + len, 16);
        printf("[%s:%d] recv %ld bytes |= encrypt => mac <%s>\n",
            inet_ntoa(me->client_address.sin_addr),
            ntohs(me->client_address.sin_port), len, me->tag_b64);
        send(me->connection, me->output, me->output_len, 0);
    }
}

static void
startup(void)
{
    crypto_init();
    enclave_key_native(&root_key);
    crypto_ds_export_public_key(&root_key.device_key, &device_pubkey);
    crypto_hash_init(&hash);
    crypto_hash_append(&hash, device_pubkey.key, device_pubkey.len);
    crypto_hash_report(&hash, device_fingerprint);
    size_t b64_len;
    crypto_b64_encode(
        device_fingerprint_b64, 96, &b64_len, device_fingerprint, 32);
    printf("sever fingerprint: %s\n", device_fingerprint_b64);
}

int
main(int argc, char** argv)
{
    startup();

    server.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server.fd < 0)
    {
        perror("Failed to create socket!\n");
    }

    int opt = 1;
    if (setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("Failed to reset socket!\n");
    }

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(21050)
    };

    if (bind(server.fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Failed to bind socket!\n");
    }

    if (listen(server.fd, 64) < 0)
    {
        perror("Failed to listen on socket!\n");
    }

    printf("server started at: %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    server.terminate = false;

    while (true)
    {
        struct worker_t* worker    = malloc(sizeof(struct worker_t));
        worker->client_address_len = sizeof(worker->client_address);
        worker->connection
            = accept(server.fd, (struct sockaddr*)&worker->client_address,
                &worker->client_address_len);
        if (worker->connection < 0)
        {
            perror("Failed to accept client!\n");
        }

        crypto_rng(worker->secrete_key, sizeof(worker->secrete_key));
        crypto_sc_mac_init(&worker->cypher, worker->secrete_key, sizeof(worker->secrete_key), true);
        crypto_b64_encode(secret_key_b64, 96, &b64_len, worker->secrete_key, sizeof(worker->secrete_key));
        printf("new client: %s:%d [key: %s]\n",
            inet_ntoa(worker->client_address.sin_addr),
            ntohs(worker->client_address.sin_port),
            secret_key_b64);

        int rv = thrd_create(&worker->thread, crypto_worker, worker);
        if (rv != thrd_success)
        {
            perror("Failed to create worker thread!\n");
        }
    }

    return 0;
}
