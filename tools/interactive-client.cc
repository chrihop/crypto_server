#include <netinet/in.h>
#include <sys/socket.h>

#include <unistd.h>
#include <cstdio>
#include <cstring>
using namespace std;

uint8_t buffer[4096];

int main(int argc, char ** argv)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(21050);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("Failed to connect to server!\n");
        return -1;
    }

    size_t len;
    ssize_t rv;
    while (true)
    {
        scanf("%s", buffer);
        len = strnlen((const char *) buffer, 4096);
        rv = send(fd, buffer, len, 0);
        if (rv == 0)
        {
            printf("[client] server closed\n");
            break ;
        }
        else if (rv != len)
        {
            perror("[client] error on tcp send, reconnect ...");
            rv = -1;
            while (rv == -1)
            {
                close(fd);
                fd = socket(AF_INET, SOCK_STREAM, 0);
                rv = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
                sleep(1);
            }
            continue ;
        }

        rv = recv(fd, buffer, 4096, 0);
        if (rv == 0)
        {
            printf("[client] server closed\n");
            break;
        }
        else if (rv < 0)
        {
            perror("[client] error on tcp recv, reconnect ...");
            rv = -1;
            while (rv == -1)
            {
                close(fd);
                fd = socket(AF_INET, SOCK_STREAM, 0);
                rv = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
                sleep(1);
            }
            continue ;
        }
        printf("recv: %lu bytes", rv);

        if (rv > 16)
        {
            printf("received %lu bytes from server\n"
                   "encrypted: ", rv);
            for (size_t i = 0; i < rv - 16; i++)
            {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
            printf("tag: ");
            for (size_t i = rv - 16; i < rv; i++)
            {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
        }
    }
    return 0;
}
