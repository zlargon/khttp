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
#include <openssl/err.h>
#endif

#define KHTTP_HOST_LEN      1024
#define KHTTP_PATH_LEN      1024
#define KHTTP_PASS_LEN      128
#define KHTTP_USER_LEN      128

#define KHTTP_REQ_SIZE      2048
#define KHTTP_SSL_DATA_LEN  256

#define KHTTP_NONCE_LEN     64
#define KHTTP_QOP_LEN       64
#define KHTTP_REALM_LEN     64
#define KHTTP_OPAQUE_LEN    64
#define KHTTP_BOUND_LEN     32

#define KHTTP_CNONCE_LEN    512
#define KHTTP_RESP_LEN      1024

#define KHTTP_HTTP_PORT     80
#define KHTTP_HTTPS_PORT    443

#define KHTTP_HEADER_MAX    32

#define KHTTP_ENABLE        1
#define KHTTP_DISABLE       0

#define KHTTP_SEND_TIMEO    10000
#define KHTTP_RECV_TIMEO    10000

#define KHTTP_SSL_DEPTH     3
#define KHTTP_NETWORK_BUF   1500


#define KHTTP_USER_AGENT    "khttp/0.1"

//#define KHTTP_DEBUG_SESS    1
//#define KHTTP_DEBUG_FLOW    1

enum{
    KHTTP_FORM_STRING,
    KHTTP_FORM_FILE
};

enum{
    KHTTP_GET,
    KHTTP_POST,
    KHTTP_PUT,
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
    KHTTP_ERR_DISCONN,
    KHTTP_ERR_NO_FD,
    KHTTP_ERR_NOT_SUPP,
    KHTTP_ERR_NO_FILE,
    KHTTP_ERR_FILE_READ,
    KHTTP_ERR_UNKNOWN
};

enum{
    KHTTP_AUTH_NONE,
    KHTTP_AUTH_DIGEST,
    KHTTP_AUTH_BASIC
};

enum{
    KHTTP_METHOD_SSLV2_3,
    KHTTP_METHOD_SSLV3,
    KHTTP_METHOD_TLSV1,
    KHTTP_METHOD_TLSV1_1,
    KHTTP_METHOD_TLSV1_2
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
    int                 header_count;
    char                *header_field[KHTTP_HEADER_MAX];
    char                *header_value[KHTTP_HEADER_MAX];
    char                host[KHTTP_HOST_LEN];
    char                path[KHTTP_PATH_LEN];
    int                 port;
    // Authentication
    int                 auth_type;
    int                 ssl_method;
    int                 pass_serv_auth;
    char                cert_path[KHTTP_PATH_LEN];
    char                key_path[KHTTP_PATH_LEN];
    char                key_pass[KHTTP_PASS_LEN];
    char                username[KHTTP_USER_LEN];
    char                password[KHTTP_PASS_LEN];
    char                realm[KHTTP_REALM_LEN];
    char                opaque[KHTTP_OPAQUE_LEN];
    char                qop[KHTTP_QOP_LEN];
    char                nonce[KHTTP_NONCE_LEN];
    char                boundary[KHTTP_BOUND_LEN];
    // Body
    size_t              body_len;
    void                *body;
    int                 done;
    char                *data;
    char                *form;
    size_t              form_len;
    int                 cont;
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
int khttp_perform(khttp_ctx *ctx);
int khttp_set_method(khttp_ctx *ctx, int method);
int khttp_set_uri(khttp_ctx *ctx, char *uri);
int khttp_ssl_set_method(khttp_ctx *ctx, int method);
int khttp_ssl_skip_auth(khttp_ctx *ctx);
int khttp_ssl_set_cert_key(khttp_ctx *ctx, char *cert, char *key, char *pw);
int khttp_set_username_password(khttp_ctx *ctx, const char *username, const char *password, int auth_type);
int khttp_set_post_data(khttp_ctx *ctx, char *data);
int khttp_set_post_form(khttp_ctx *ctx, char *key, char *value, int type);
const char * khttp_code_description(int code);
int khttp_set_log_callback(int (* callback)(const char * file, const char * tag, const char * level, int line, const char * func, const char * message));
#endif
