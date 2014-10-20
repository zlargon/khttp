#ifndef __KHTTP_H
#define __KHTTP_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "http_parser.h"

#ifdef OPENSSL
#include <openssl/ssl.h>
#include <openssl/md5.h>
#endif

#define KHTTP_HOST_LEN      1024
#define KHTTP_PATH_LEN      1024
#define KHTTP_PATH_LEN      1024
#define KHTTP_PASS_LEN      128
#define KHTTP_USER_LEN      128

#define KHTTP_HTTP_PORT     80
#define KHTTP_HTTPS_PORT    443

#define KHTTP_HEADER_MAX    16

#define KHTTP_ENABLE        1
#define KHTTP_DISABLE       0

#define KHTTP_SEND_TIMEO    10000
#define KHTTP_RECV_TIMEO    10000

#define KHTTP_SSL_DEPTH     1

enum{
    KHTTP_GET,
    KHTTP_POST,
    KHTTP_UPDATE,
    KHTTP_DELETE
};

enum{
    KHTTP_ERR_OK,
    KHTTP_ERR_TIMEOUT,
    KHTTP_ERR_DNS,
    KHTTP_ERR_SOCK,
    KHTTP_ERR_SSL,
    KHTTP_ERR_OOM,
    KHTTP_ERR_SEND,
    KHTTP_ERR_RECV,
    KHTTP_ERR_PARAM,
    KHTTP_ERR_CONNECT,
    KHTTP_ERR_NO_FD,
    KHTTP_ERR_UNKNOWN
};

enum{
    KHTTP_AUTH_NONE,
    KHTTP_AUTH_DIGEST,
    KHTTP_AUTH_BASIC
};

enum{
    KHTTP_HTTP,
    KHTTP_HTTPS
};

struct khttp_resp {
    int                 body_len;
    void                *body;
};

typedef struct khttp_ctx {
    int                 fd;
    struct sockaddr_in  serv_addr;
    int                 proto;                          //KHTTP_HTTP / KHTTP_HTTPS
    int                 method;                         //KHTTP_GET / KHTTP_POST
    char                *header[KHTTP_HEADER_MAX];
    char                host[KHTTP_HOST_LEN];
    char                path[KHTTP_PATH_LEN];
    int                 port;
    int                 pass_serv_auth;
    char                cert_path[KHTTP_PATH_LEN];
    char                key_path[KHTTP_PATH_LEN];
    char                key_pass[KHTTP_PASS_LEN];
    char                username[KHTTP_USER_LEN];
    char                password[KHTTP_PASS_LEN];
    int                 body_len;
    void                *body;
    http_parser         hp;
#ifdef OPENSSL
    BIO                 *bio;
    SSL_CTX             *ssl_ctx;
    SSL                 *ssl;
#endif
    struct timeval      timeout;
    struct khttp_resp   resp;
    int (*send)(struct khttp_ctx *, void *, int, int);
    int (*recv)(struct khttp_ctx *, void *, int, int);
}khttp_ctx;

khttp_ctx *khttp_new();
void khttp_destroy(khttp_ctx *ctx);
#endif
