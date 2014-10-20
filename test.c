#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>

#include <netinet/tcp.h>
#include "http_parser.h"

#include "khttp.h"

static void khttp_nonblock_socket(int sk)
{
    unsigned long fc = 1;
    ioctl(sk, FIONBIO, &fc);
}
struct http_resp{
    char *body;
    int len;
};
int
body_cb (http_parser *p, const char *buf, size_t len)
{
    struct http_resp *data = p->data;
    data->body = realloc(data->body, len + data->len);
    memcpy(data->body + data->len, buf, len);
    printf("--------------------------- %zu\n", len);
  //snprintf(stdout, len,"%s",buf);
  // printf("body_cb: '%s'\n", requests[num_messages].body);
  return 0;
}
int
message_complete_cb (http_parser *p)
{
    printf("message completed\n");
  printf("Final:%d\n",http_body_is_final(p));
    return 0;
}
static http_parser_settings settings_null =
  {.on_message_begin = 0
  ,.on_header_field = 0
  ,.on_header_value = 0
  ,.on_url = 0
  ,.on_status = 0
  ,.on_body = body_cb
  ,.on_headers_complete = 0
  ,.on_message_complete = message_complete_cb
};

int main()
{
    khttp_ctx *ctx = khttp_new();
    http_parser hp;
    struct addrinfo hints;
    struct addrinfo *server;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    struct sockaddr_in  srv_addr;
    int r = getaddrinfo("www.inside.com.tw", NULL, &hints, &server);
    srv_addr.sin_addr = ((struct sockaddr_in *) (server->ai_addr))->sin_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(80);

    int sk = socket(AF_INET, SOCK_STREAM, 0);
    if(sk < 0){
        printf("error open socket\n");
        return -1;
    }
    freeaddrinfo(server);
    if((r = connect(sk, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr)))< 0){
        printf("error on connect\n");
        return -1;
    }
    khttp_nonblock_socket(sk);
    char buf[1024];
    int len = snprintf(buf, 1024, "GET / HTTP/1.1\r\n"
        "Host: www.inside.com.tw\r\n"
        "Accept: */*\r\n"
        "User-Agent: khttp/agent\r\n"
        "\r\n");
    printf("%s", buf);
    r = send(sk, buf, len, 0);
    int ready = 0;
    http_parser_init(&hp, HTTP_RESPONSE);
    int nparsed = 0;
    char *body = NULL;
    char *out = NULL;
    struct http_resp *resp = malloc(sizeof(struct http_resp));
    hp.data = resp;
    int total = 0;
    while(1){
        memset(buf, 0, 1024);
        r = recv(sk, buf, 1024, 0);
        if(r > 0){
            ready = 1;
            //printf("=========%d bytes\n%s\n",total, body);
            body = realloc(body, total + r);
            memcpy(body + total, buf, r);
            total += r;
            usleep(100000);
        }else{
            if(ready == 1){
            printf("=========%d bytes\n%s\n",total, body);
            nparsed = http_parser_execute(&hp, &settings_null, body, total);
            break;
            }
        }
    }
    return 0;
}
