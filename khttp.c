#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <resolv.h>  // res_init, also include <arpa/nameser.h>
#include "khttp.h"

static int khttp_socket_reuseaddr(int fd, int enable);
static char *khttp_base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
static size_t khttp_file_size(char *file);
static const char *khttp_auth2str(int type);
static const char *khttp_type2str(int type);
static int khttp_body_cb (http_parser *p, const char *buf, size_t len);
static int khttp_response_status_cb (http_parser *p, const char *buf, size_t len);
static int khttp_message_complete_cb (http_parser *p);
static int khttp_header_field_cb (http_parser *p, const char *buf, size_t len);
static int khttp_header_value_cb (http_parser *p, const char *buf, size_t len);
static char *khttp_find_header(khttp_ctx *ctx, const char *header);
static int khttp_field_copy(char *in, char *out, int len);
static int khttp_parse_auth(khttp_ctx *ctx, char *value);
static void khttp_free_header(khttp_ctx *ctx);
static void khttp_free_body(khttp_ctx *ctx);
static int khttp_socket_create();
static int khttp_md5sum(char *input, int len, char *out);
static void khttp_copy_host(char *in, char *out);
static void khttp_dump_message_flow(char *data, int len, int way);
static int http_send(khttp_ctx *ctx, void *buf, int len, int timeout);
static int https_send(khttp_ctx *ctx, void *buf, int len, int timeout);
static int http_recv(khttp_ctx *ctx, void *buf, int len, int timeout);
static int https_recv(khttp_ctx *ctx, void *buf, int len, int timeout);
static int khttp_send_http_req(khttp_ctx *ctx);
static int khttp_send_form(khttp_ctx *ctx);
static int khttp_send_http_auth(khttp_ctx *ctx);
static int khttp_recv_http_resp(khttp_ctx *ctx);

// KHTTP Log
#define KHTTP_MESSAGE_MAX_LEN  2048
#define khttp_debug(fmt, agrs...) khttp_log(KHTTP_LOG_DEBUG, __LINE__, __func__, fmt, ##agrs)
#define khttp_info(fmt,  agrs...) khttp_log(KHTTP_LOG_INFO,  __LINE__, __func__, fmt, ##agrs)
#define khttp_warn(fmt,  agrs...) khttp_log(KHTTP_LOG_WARN,  __LINE__, __func__, fmt, ##agrs)
#define khttp_error(fmt, agrs...) khttp_log(KHTTP_LOG_ERROR, __LINE__, __func__, fmt, ##agrs)
static void khttp_log(int level, int line, const char * func, const char * format, ...);
static void (* khttp_log_callback)(const char * file, const char * tag, int level, int line, const char * func, const char * message) = NULL;

#ifdef OPENSSL
static int ssl_ca_verify_cb(int ok, X509_STORE_CTX *store);
static int khttp_ssl_setup(khttp_ctx *ctx);
#endif

static const struct {
    char text[8];
}method_type[]={
    {"GET"},
    {"POST"},
    {"PUT"},
    {"DELETE"}
};

static const struct {
    char text[8];
}auth_type[]={
    {"None"},
    {"Digest"},
    {"Basic"}
};

static char base64_encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

static char *khttp_base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length+1);
    if (encoded_data == NULL) return NULL;
    memset(encoded_data, 0, *output_length);
    int i,j;
    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

static size_t khttp_file_size(char *file)
{
    if(!file) return -1;
    size_t len = -1;
    FILE *fp = fopen(file, "r");
    if(fp){
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fclose(fp);
    }
    return len;
}

static const char *khttp_auth2str(int type)
{
    return auth_type[type].text;
}
static const char *khttp_type2str(int type)
{
    return method_type[type].text;
}

static int khttp_body_cb (http_parser *p, const char *buf, size_t len)
{
    khttp_ctx *ctx = p->data;
    char *head = ctx->body;
    if(ctx->done == 1){ //Parse done copy body
        int offset = ctx->body_len;
        //printf("-------------%zu offset %d\n%s\n", len, offset,buf);
        memcpy(head + offset, buf, len);
    }
    ctx->body_len += len;
    //khttp_debug("body callbacked length:%zu\n", len);
    return 0;
}

static int khttp_response_status_cb (http_parser *p, const char *buf, size_t len)
{
#ifndef KHTTP_DEBUG
    return 0;
#else
    char *tmp = malloc(len + 1);
    if(!tmp) return 0;
    tmp[len] = 0;
    memcpy(tmp, buf, len);
    khttp_debug("khttp status code %s\n", tmp);
    free(tmp);
    return 0;
#endif
}

static int khttp_message_complete_cb (http_parser *p)
{
    khttp_ctx *ctx = p->data;
    ctx->done = 1;
    return 0;
}

static int khttp_header_field_cb (http_parser *p, const char *buf, size_t len)
{
    khttp_ctx *ctx = p->data;
    if(ctx->done == 1){
        char *tmp = malloc(len + 1);
        if(!tmp) return -KHTTP_ERR_OOM;
        tmp[len] = 0;
        ctx->header_field[ctx->header_count] = tmp;
        memcpy(tmp, buf, len);
        //printf("%d header field: %s ||||| ", ctx->header_count, tmp);
    }
    return 0;
}

static int khttp_header_value_cb (http_parser *p, const char *buf, size_t len)
{
    khttp_ctx *ctx = p->data;
    if(ctx->done == 1){
        char *tmp = malloc(len + 1);
        if(!tmp) return -KHTTP_ERR_OOM;
        tmp[len] = 0;
        ctx->header_value[ctx->header_count] = tmp;
        memcpy(tmp, buf, len);
        //printf(" header value: %s\n", tmp);
        ctx->header_count ++;
    }
    return 0;
}

static char *khttp_find_header(khttp_ctx *ctx, const char *header)
{
    if(!ctx) return NULL;
    int i = 0;
    for(i = 0; i < ctx->header_count ; i++){
        if(strncmp(header, ctx->header_field[i], strlen(header)) == 0) {
            //printf("match %02d %20s     %s\n", i , ctx->header_field[i], ctx->header_value[i]);
            return ctx->header_value[i];
        }
    }
    return NULL;
}

static int khttp_field_copy(char *in, char *out, int len)
{
    if(in == NULL || out == NULL) return -1;
    int i = 0;
    for(i = 0; i < strlen(in); i ++ ){
        if(in[i] != '"') {
            out[i] = in[i];
        }else{
            out[i] = 0;
            break;
        }
    }
    return 0;
}

static int khttp_parse_auth(khttp_ctx *ctx, char *value)
{
    char *realm;
    char *nonce;
    char *qop;
    char *opaque;
    char *ptr = value;
    if(strncmp(ptr, "Digest", 6) == 0){
        ctx->auth_type = KHTTP_AUTH_DIGEST;
        if((realm = strstr(ptr, "realm")) != NULL){
            realm = realm + strlen("realm:\"");
            khttp_field_copy(realm, ctx->realm, KHTTP_REALM_LEN);
        }
        if((nonce = strstr(ptr, "nonce")) != NULL){
            nonce = nonce + strlen("nonce:\"");
            khttp_field_copy(nonce, ctx->nonce, KHTTP_NONCE_LEN);
        }
        if((opaque = strstr(ptr, "opaque")) != NULL){
            opaque = opaque + strlen("opaque:\"");
            khttp_field_copy(opaque, ctx->opaque, KHTTP_OPAQUE_LEN);
        }
        if((qop = strstr(ptr, "qop")) != NULL){
            qop = qop + strlen("qop:\"");
            khttp_field_copy(qop, ctx->qop, KHTTP_QOP_LEN);
        }
    }else if(strncmp(ptr, "Basic", 5) == 0){
        ctx->auth_type = KHTTP_AUTH_BASIC;
    }
    //Digest realm="Users", nonce="KYRxkHxBfiylcOAMM3YiUPWqzUkdgv8y", qop="auth"
    return 0;
}

static void khttp_free_header(khttp_ctx *ctx)
{
    if(!ctx) return;
    int i = 0;
    for(i = 0; i < ctx->header_count ; i++){
        if(ctx->header_field[i]) {
            free(ctx->header_field[i]);
            ctx->header_field[i] = NULL;
        }
        if(ctx->header_value[i]) {
            free(ctx->header_value[i]);
            ctx->header_value[i] = NULL;
        }
    }
    ctx->header_count = 0;
}

static void khttp_free_body(khttp_ctx *ctx)
{
    if(ctx->body){
        free(ctx->body);
        ctx->body = NULL;
    }
    ctx->done = 0;
}

static http_parser_settings http_parser_cb =
{
    .on_message_begin       = 0
    ,.on_header_field       = khttp_header_field_cb
    ,.on_header_value       = khttp_header_value_cb
    ,.on_url                = 0
    ,.on_status             = khttp_response_status_cb
    ,.on_body               = khttp_body_cb
    ,.on_headers_complete   = 0
    ,.on_message_complete   = khttp_message_complete_cb
};

khttp_ctx *khttp_new()
{
    unsigned char rands[8];
    khttp_ctx *ctx = malloc(sizeof(khttp_ctx));
    if(!ctx){
        khttp_error("khttp context create failure out of memory\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(khttp_ctx));

    // set default content-type as application/x-www-form-urlencoded
    sprintf(ctx->content_type, "%s", "application/x-www-form-urlencoded");

#ifdef KHTTP_USE_URANDOM
    FILE *fp = fopen("/dev/urandom", "r");
    if(fp){
        size_t len = fread(rands, 1, 8, fp);
        sprintf(ctx->boundary, "%02x%02x%02x%02x%02x%02x%02x%02x",
                rands[0], rands[1], rands[2], rands[3],
                rands[4], rands[5], rands[6], rands[7]
                );
        fclose(fp);
    }else{
#else
    if(1){
#endif
        srand (time(NULL));
        int r = rand();
        rands[0] = r >> 24;
        rands[1] = r >> 16;
        rands[2] = r >> 8;
        rands[3] = r;
        srand(r);
        r = rand();
        rands[4] = r >> 24;
        rands[5] = r >> 16;
        rands[6] = r >> 8;
        rands[7] = r;
        sprintf(ctx->boundary, "%02x%02x%02x%02x%02x%02x%02x%02x",
                rands[0], rands[1], rands[2], rands[3],
                rands[4], rands[5], rands[6], rands[7]
                );
        //TODO random generate boundary
    }
    return ctx;
}

void khttp_destroy(khttp_ctx *ctx)
{
    if(!ctx) return;
    khttp_free_header(ctx);
    khttp_free_body(ctx);
#ifdef OPENSSL
    if(ctx->ssl){
        SSL_set_shutdown(ctx->ssl, 2);
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        if(ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    }
#endif
    if(ctx->fd > 0) close(ctx->fd);
    if(ctx->body) {
        free(ctx->body);
        ctx->body = NULL;
    }
    if(ctx->data) {
        free(ctx->data);
        ctx->data = NULL;
    }
    if(ctx->form) {
        free(ctx->form);
        ctx->form = NULL;
    }
    if(ctx){
        free(ctx);
    }
}

static int khttp_socket_create()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        khttp_error("khttp socket create failure %d(%s)\n", errno, strerror(errno));
        return fd;
    }
    //Default enable nonblock / reuseaddr and set send / recv timeout
    khttp_socket_reuseaddr(fd, 1);
    return fd;
}

static int khttp_socket_reuseaddr(int fd, int enable)
{
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable));
    if(ret != 0){
        khttp_warn("khttp set socket reuseaddr failure %d(%s)\n", errno, strerror(errno));
    }
    return ret;
}

static int khttp_md5sum(char *input, int len, char *out)
{
    int ret = 0;
#ifdef OPENSSL
    MD5_CTX ctx;
    char buf[3] = {'\0'};
    unsigned char md5[MD5_DIGEST_LENGTH];
    if(input == NULL || len < 1 || out == NULL)
        return -1;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, len);
    MD5_Final(md5, &ctx);
    out[0] = '\0';

    int i;
    for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(buf, "%02x", md5[i]);
        strcat(out, buf);
    }
#else
//#error "FIXME NO OPENSSL"
#endif
    //khttp_debug("MD5:[%s]\n", out);
    return ret;
}

int khttp_set_method(khttp_ctx *ctx, int method)
{
    if(method < KHTTP_GET || method > KHTTP_DELETE){
        khttp_error("khttp set method parameter out of range\n");
        return -KHTTP_ERR_PARAM;
    }
    ctx->method = method;
    return KHTTP_ERR_OK;
}

int khttp_set_content_type(khttp_ctx * ctx, const char * content_type) {
    if (ctx == NULL) {
        khttp_error("khttp_ctx should not be null\n");
        return -KHTTP_ERR_PARAM;
    }

    if (content_type == NULL || strlen(content_type) <= 0) {
        khttp_error("content_type should not be null or empty\n");
        return -KHTTP_ERR_PARAM;
    }

    // set content type
    memset(ctx->content_type, 0, KHTTP_CONTENT_TYPE_LEN);
    sprintf(ctx->content_type, "%s", content_type);
    return KHTTP_ERR_OK;
}

static void khttp_copy_host(char *in, char *out)
{
    int i = 0;
    for(i=0 ; i<strlen(in) ; i++) {
        if(in[i] == ':' || in[i] == '/' || in[i] == '\0') break;
        out[i] = in[i];
    }
}

static void khttp_dump_message_flow(char *data, int len, int way)
{
#ifdef KHTTP_DEBUG_SESS
    //data[len]  = 0;
    printf("----------------------------------------------\n");
    if(way == 0){
        printf("          Client   >>>    Server\n");
    }else{
        printf("          Server   >>>    Client\n");
    }
    printf("----------------------------------------------\n");
    printf("%s\n", data);
    printf("----------------------------------------------\n");
#endif
}

static int http_send(khttp_ctx *ctx, void *buf, int len, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000 )  * 1000;
    if(ctx->fd < 0) return -KHTTP_ERR_NO_FD;
    int sent = 0;
    char *head = buf;
    do {
        fd_set fs;
        FD_ZERO(&fs);
        FD_SET(ctx->fd, &fs);
        int ret = select(ctx->fd +1, NULL, &fs, NULL, &tv);
        if(ret >= 0){
            // ret == 0 handle?
            //khttp_debug("send:\n%s\nfd:%d\n", head, ctx->fd);
            ret = send(ctx->fd, head + sent, len - sent, 0);
            if(ret > 0) {
                sent += ret;
            } else {
                khttp_error("khttp send error %d (%s)\n", errno, strerror(errno));
                return -KHTTP_ERR_SEND;
            }
        }else{
            return -KHTTP_ERR_DISCONN;
        }
    }while(sent < len);
    return KHTTP_ERR_OK;
}
#ifdef OPENSSL

static int https_send(khttp_ctx *ctx, void *buf, int len, int timeout)
{
    int sent = 0;
    char *head = buf;
    struct timeval tv;
    int ret = KHTTP_ERR_OK;
    int retry = 3;//FIXME define in header
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    if(ctx->fd < 0) return -KHTTP_ERR_NO_FD;
    do {
        fd_set fs;
        FD_ZERO(&fs);
        FD_SET(ctx->fd, &fs);
        int res = select(ctx->fd + 1, NULL, &fs, NULL, &tv);
        if(res >= 0){
            //khttp_debug("send data...\n");
            res = SSL_write(ctx->ssl, head + sent, len - sent);
            if(res > 0){
                sent += res;
            }else if(errno == -EAGAIN && retry != 0){
                retry--;
            }else{
                ret = -KHTTP_ERR_SEND;
                break;
            }
        }else{
            ret = -KHTTP_ERR_DISCONN;
            break;
        }
    }while(sent < len);
    //khttp_debug("send https success\n%s\n", (char *)buf);
    return ret;
}
#endif

static int http_recv(khttp_ctx *ctx, void *buf, int len, int timeout)
{
    int ret = KHTTP_ERR_OK;
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000)  * 1000;
    if(ctx->fd < 0) return -KHTTP_ERR_NO_FD;
    fd_set fs;
    FD_ZERO(&fs);
    FD_SET(ctx->fd, &fs);
    ret = select(ctx->fd + 1, &fs, NULL, NULL, &tv);
    if(ret >= 0) {
        if(ret == 0) {
            khttp_error("khttp recv timeout\n");
        }
        ret = recv(ctx->fd, buf, len, 0);
        if(ret < 0) {
            khttp_error("khttp recv error %d (%s)\n", errno, strerror(errno));
            return -KHTTP_ERR_RECV;
        }
    }else{
        khttp_error("khttp recv select error %d (%s)\n", errno, strerror(errno));
    }
    return ret;
}
#ifdef OPENSSL

static int https_recv(khttp_ctx *ctx, void *buf, int len, int timeout)
{
    if(ctx == NULL || buf == NULL || len <= 0) return -KHTTP_ERR_PARAM;
    int ret = KHTTP_ERR_OK;
    int res = 0;
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    if(SSL_pending(ctx->ssl) > 0){
        //data available
        res = SSL_read(ctx->ssl, buf, len);
        if(res <= 0){
            khttp_error("SSL_read  error %d(%s)\n", errno, strerror(errno));
            ret = -KHTTP_ERR_RECV;
            goto end;
        }
        ret = res;
    }else{
        //data not available select socket
        fd_set fs;
        FD_ZERO(&fs);
        FD_SET(ctx->fd, &fs);
        res = select(ctx->fd + 1, &fs, NULL, NULL, &tv);
        if(res < 0){
            khttp_error("https select error %d(%s)\n", errno, strerror(errno));
            ret = -KHTTP_ERR_RECV;
            goto end;
        }else if(res == 0){
            khttp_error("https select timeout\n");
            ret = -KHTTP_ERR_TIMEOUT;
            goto end;
        }
        res = SSL_read(ctx->ssl, buf, len);
        if(res <= 0){
            khttp_error("SSL_read  error %d(%s)\n", errno, strerror(errno));
            ret = -KHTTP_ERR_RECV;
            goto end;
        }
        ret = res;
    }
end:
    return ret;
}
#endif

int khttp_set_uri(khttp_ctx *ctx, char *uri)
{
    char *head = uri;
    char *host = NULL;
    char *path = NULL;
    char *port = NULL;

    if(!ctx || !uri){
        return KHTTP_ERR_PARAM;
    }
    if(strncasecmp(uri, "https://", 8) == 0) {
        ctx->proto = KHTTP_HTTPS;
        host = head + 8;
#ifdef OPENSSL
        ctx->send = https_send;
        ctx->recv = https_recv;
#else
//#error "FIXME NO OPENSSL"
#endif
    } else if(strncasecmp(uri, "http://", 7) == 0) {
        ctx->proto = KHTTP_HTTP;
        host = head + 7;
        ctx->send = http_send;
        ctx->recv = http_recv;
    } else {
        ctx->proto = KHTTP_HTTP;
        host = head;
        ctx->send = http_send;
        ctx->recv = http_recv;
    }
    if((path = strchr(host, '/'))!= NULL) {
        strncpy(ctx->path, path, KHTTP_PATH_LEN);
    } else {
        strcpy(ctx->path, "/");
    }
    if((port = strchr(host, ':'))!= NULL) {
        ctx->port = atoi(port + 1);
        if(ctx->port < 1 || ctx->port > 65535){
            khttp_error("khttp set port out of range: %d! use default port\n", ctx->port);
            if(ctx->proto == KHTTP_HTTPS) ctx->port = 443;
            else ctx->port = 80;
        }
    } else {
        // No port. Set default port number
        if(ctx->proto == KHTTP_HTTPS) ctx->port = 443;
        else ctx->port = 80;
    }
    khttp_copy_host(host, ctx->host);
    return KHTTP_ERR_OK;
}
#ifdef OPENSSL
static int ssl_ca_verify_cb(int ok, X509_STORE_CTX *store)
{
    int depth, err;
    X509 *cert = NULL;
    char data[KHTTP_SSL_DATA_LEN];
    if(!ok) {
        cert = X509_STORE_CTX_get_current_cert(store);
        depth = X509_STORE_CTX_get_error_depth(store);
        err = X509_STORE_CTX_get_error(store);
        khttp_debug("Error with certificate at depth: %i", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, KHTTP_SSL_DATA_LEN);
        khttp_debug(" issuer = %s", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, KHTTP_SSL_DATA_LEN);
        khttp_debug(" subject = %s", data);
        khttp_debug(" err %i:%s", err, X509_verify_cert_error_string(err));
        return 0;
    }
    return ok;
}

static int khttp_ssl_setup(khttp_ctx *ctx) {

    // only init SSL library once
    static bool ssl_is_init = false;
    if (ssl_is_init == false) {
        SSL_library_init();         // always return 1
        SSL_load_error_strings();
        ssl_is_init = true;
    }

    int ret = 0;
    if(ctx->ssl_method == KHTTP_METHOD_SSLV2_3){
        if( (ctx->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
            khttp_error("SSL setup request method SSLv23 failure\n");
            return -KHTTP_ERR_SSL;
        }
    }else if(ctx->ssl_method == KHTTP_METHOD_SSLV3){
        if( (ctx->ssl_ctx = SSL_CTX_new(SSLv3_client_method())) == NULL) {
            khttp_error("SSL setup request method SSLv3 failure\n");
            return -KHTTP_ERR_SSL;
        }
    }else if(ctx->ssl_method == KHTTP_METHOD_TLSV1){
        if( (ctx->ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL) {
            khttp_error("SSL setup request method TLSv1 failure\n");
            return -KHTTP_ERR_SSL;
        }
#if (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(__ANDROID__) && !defined(__MAC__)
    }else if(ctx->ssl_method == KHTTP_METHOD_TLSV1_1){
        if( (ctx->ssl_ctx = SSL_CTX_new(TLSv1_1_client_method())) == NULL) {
            khttp_error("SSL setup request method TLSv1_1 failure\n");
            return -KHTTP_ERR_SSL;
        }
    }else if(ctx->ssl_method == KHTTP_METHOD_TLSV1_2){
        if( (ctx->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
            khttp_error("SSL setup request method TLSv1_2 failure\n");
            return -KHTTP_ERR_SSL;
        }
#endif
    }else{
        //Not going happen
    }
    // Pass server auth
    if(ctx->pass_serv_auth){
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }else{
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, ssl_ca_verify_cb);
        SSL_CTX_set_verify_depth(ctx->ssl_ctx, KHTTP_SSL_DEPTH);
        if(SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->cert_path, NULL) != 1){
            khttp_error("khttp not able to load certificate on path: %s\n", ctx->cert_path);
        }
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx->ssl_ctx, ctx->key_pass);
    if(SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, ctx->cert_path) == 1) {
        khttp_debug("khttp load certificate success\n");
    }
    if(SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->key_path, SSL_FILETYPE_PEM) == 1) {
        khttp_debug("khttp load private key success\n");
    }
    if(SSL_CTX_check_private_key(ctx->ssl_ctx) == 1) {
        khttp_debug("khttp check private key success\n");
    }
    if((ctx->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
        khttp_error("create SSL failure\n");
        return -KHTTP_ERR_SSL;
    }
    if((ret = SSL_set_fd(ctx->ssl, ctx->fd)) != 1) {
        ret = SSL_get_error(ctx->ssl, ret);
        khttp_error("set SSL fd failure %d\n", ret);
        return -KHTTP_ERR_SSL;
    }

    /* non-blocking SSL connect */
    int flags = fcntl(ctx->fd, F_GETFL);            // save fd status flags
    fcntl(ctx->fd, F_SETFL, flags | O_NONBLOCK);    // add non-blocking flag to fd

    // http://stackoverflow.com/questions/18127031/how-to-set-ssl-connect-on-non-blocking-socket-with-select-on-linux-platform
    while ((ret = SSL_connect(ctx->ssl)) != 1) {
        int error = SSL_get_error(ctx->ssl, ret);
        switch (error) {

            // 1. Read and Write
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE: {

                fd_set fs;
                FD_ZERO(&fs);
                FD_SET(ctx->fd, &fs);

                struct timeval tv = {
                    .tv_sec = 5     // 5 seconds timeout
                };

                int select_ret = select(ctx->fd + 1, &fs, NULL, NULL, &tv);
                if (select_ret <= 0) {
                    khttp_error("SSL_connect select timeout or failed, ret = %d\n", select_ret);
                    return -KHTTP_ERR_SSL;
                }

                /* SSL_connect is still in progress */
                /* invoke SSL_connect function again */
                break;
            }

            // 2. Certificate Error
            case 0x1470E086:    // SSL2_SET_CERTIFICATE
            case 0x14090086: {  // SSL3_GET_SERVER_CERTIFICATE
                long cert_err = SSL_get_verify_result(ctx->ssl);
                if (cert_err != X509_V_OK) {
                    khttp_error("SSL certificate problem: %s (%ld)\n", X509_verify_cert_error_string(cert_err), cert_err);
                }
                return -KHTTP_ERR_SSL;
            }

            // 3. the others error
            default: {
                char error_string[256] = {0};
                ERR_error_string_n(error, error_string, sizeof(error_string));
                khttp_error("SSL_connect error: %s (%d)\n", error_string, error);
                return -KHTTP_ERR_SSL;
            }
        }
    }

    // set fd back to origin status flags
    fcntl(ctx->fd, F_SETFL, flags);

    // khttp_debug("Connect to SSL server success\n");
    return KHTTP_ERR_OK;
}

int khttp_ssl_set_method(khttp_ctx *ctx, int method)
{
    if(method >= KHTTP_METHOD_SSLV2_3 && method <= KHTTP_METHOD_TLSV1_2){
        ctx->ssl_method = method;
    }
    return KHTTP_ERR_OK;
}

int khttp_ssl_skip_auth(khttp_ctx *ctx)
{
    ctx->pass_serv_auth = 1;
    return KHTTP_ERR_OK;
}

int khttp_ssl_set_cert_key(khttp_ctx *ctx, char *cert, char *key, char *pw)
{
    if(ctx == NULL || cert == NULL || key == NULL) return -KHTTP_ERR_PARAM;
    if(khttp_file_size(cert) <= 0) return -KHTTP_ERR_NO_FILE;
    if(khttp_file_size(key) <= 0) return -KHTTP_ERR_NO_FILE;
    strncpy(ctx->cert_path, cert, KHTTP_PATH_LEN);
    strncpy(ctx->key_path, key, KHTTP_PATH_LEN);
    if(pw) strncpy(ctx->key_pass, pw, KHTTP_PASS_LEN);
    return KHTTP_ERR_OK;
}
#endif

int khttp_set_username_password(khttp_ctx *ctx, const char *username, const char *password, int auth_type)
{
    if(ctx == NULL || username == NULL || password == NULL) return -KHTTP_ERR_PARAM;
    strncpy(ctx->username, username, KHTTP_USER_LEN);
    strncpy(ctx->password, password, KHTTP_PASS_LEN);
    if(auth_type == KHTTP_AUTH_DIGEST){
        ctx->auth_type = KHTTP_AUTH_DIGEST;
    }else{
        //Default auth type is basic if auth_type not define
        ctx->auth_type = KHTTP_AUTH_BASIC;
    }
    return KHTTP_ERR_OK;
}

int khttp_set_post_data(khttp_ctx *ctx, char *data)
{
    if(ctx == NULL || data == NULL) return -KHTTP_ERR_PARAM;
    if(ctx->data) free(ctx->data);
    //Malloc memory from data string length. Should be protect?
    ctx->data = malloc(strlen(data) + 1);
    if(!ctx->data) return -KHTTP_ERR_OOM;
    //Copy from data
    strcpy(ctx->data, data);
    return KHTTP_ERR_OK;
}

int khttp_set_post_form(khttp_ctx *ctx, char *key, char *value, int type)
{
    if(ctx == NULL || key == NULL || value == NULL || type < KHTTP_FORM_STRING || type > KHTTP_FORM_FILE) return -KHTTP_ERR_PARAM;
    if(type == KHTTP_FORM_STRING){
        size_t offset = ctx->form_len;
        ctx->form_len = ctx->form_len + 44 + strlen("Content-Disposition: form-data; name=\"\"\r\n\r\n") + 2;
        ctx->form_len = ctx->form_len + strlen(key) + strlen(value);
        ctx->form = realloc(ctx->form, ctx->form_len + 1);
        if(ctx->form == NULL) return -KHTTP_ERR_OOM;
        char *head = ctx->form + offset;
        sprintf(head, "--------------------------%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"\r\n\r\n"
                "%s\r\n"
                ,ctx->boundary
                ,key
                ,value
                );
    }else{
        //TODO add file type checking
        //text/plain or application/octet-stream
        size_t offset = ctx->form_len;
        ctx->form_len = ctx->form_len + 44 + strlen("Content-Disposition: form-data; name=\"\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n") + 2;
        //origin size + end boundary + header + file end(\r\n)
        size_t file_size = khttp_file_size(value);
        if(file_size <= 0){
            khttp_error("File %s not exist\n",value);
            return -KHTTP_ERR_NO_FILE;
        }
        //Calculate the latest form length
        ctx->form_len = ctx->form_len + strlen(key) + file_size + strlen(value);
        ctx->form = realloc(ctx->form, ctx->form_len + 1);
        if(ctx->form == NULL) return -KHTTP_ERR_OOM;
        //Write the next header
        char *head = ctx->form + offset;
        int head_len = sprintf(head, "--------------------------%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n"
                ,ctx->boundary
                ,key
                ,value
                );
        head = head + head_len;//Offset header
        FILE *fp = fopen(value, "r");
        if(fp){
            if(fread(head , 1, file_size, fp) != file_size){
                khttp_error("read file failure\n");
                fclose(fp);
                return -KHTTP_ERR_FILE_READ;
            }
            fclose(fp);
        }
        head = head + file_size;
        head[0] = '\r';
        head[1] = '\n';
        head[2] = 0;
        //khttp_debug("\n%s\n", ctx->form);
    }
    return KHTTP_ERR_OK;
}

static int khttp_send_http_req(khttp_ctx *ctx)
{
    char resp_str[KHTTP_RESP_LEN];
    //FIXME change to dynamic size
    char *req = malloc(KHTTP_REQ_SIZE);
    if(!req) return -KHTTP_ERR_OOM;

    memset(req, 0, KHTTP_REQ_SIZE);
    int len = 0;
    if(ctx->method == KHTTP_GET) {
        if(ctx->auth_type == KHTTP_AUTH_BASIC){
            len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s", ctx->username, ctx->password);
            size_t base64_len;
            char *base64 = khttp_base64_encode((unsigned char *) resp_str, len, &base64_len);
            if(!base64) return -KHTTP_ERR_OOM;
            len = snprintf(req, KHTTP_REQ_SIZE, "GET %s HTTP/1.1\r\n"
                "Authorization: Basic %s\r\n"
                "User-Agent: %s\r\n"
                "Host: %s\r\n"
                "Accept: */*\r\n"
                "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host);
            //TODO add len > KHTTP_REQ_SIZE handle
            free(base64);
            base64 = NULL;
        }else{
            len = snprintf(req, KHTTP_REQ_SIZE, "GET %s HTTP/1.1\r\n"
                "User-Agent: %s\r\n"
                "Host: %s\r\n"
                "Accept: */*\r\n"
                "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host);
        }
    }else if(ctx->method == KHTTP_POST){
        if(ctx->auth_type == KHTTP_AUTH_BASIC){
            len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s", ctx->username, ctx->password);
            size_t base64_len;
            char *base64 = khttp_base64_encode((unsigned char *) resp_str, len, &base64_len);
            if(!base64) return -KHTTP_ERR_OOM;
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE, "POST %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host, strlen(ctx->data), ctx->content_type);
            }else if(ctx->form){
                len = snprintf(req, KHTTP_REQ_SIZE, "POST %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Expect: 100-continue\r\n"
                    "Content-Type: multipart/form-data; boundary=------------------------%s\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host, ctx->form_len + 44, ctx->boundary);
                //FIXME change the Content-Type to dynamic like application/x-www-form-urlencoded or application/json...
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE, "POST %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host);
                //TODO add len > KHTTP_REQ_SIZE handle
            }
            free(base64);
            base64 = NULL;
        }else{
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE, "POST %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host, strlen(ctx->data), ctx->content_type);
            }else if(ctx->form){
                len = snprintf(req, KHTTP_REQ_SIZE, "POST %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Expect: 100-continue\r\n"
                    "Content-Type: multipart/form-data; boundary=------------------------%s\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host, ctx->form_len + 46, ctx->boundary);
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE, "POST %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host);
            }
        }
    }else if(ctx->method == KHTTP_PUT){
        if(ctx->auth_type == KHTTP_AUTH_BASIC){
            len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s", ctx->username, ctx->password);
            size_t base64_len;
            char *base64 = khttp_base64_encode((unsigned char *) resp_str, len, &base64_len);
            if(!base64) return -KHTTP_ERR_OOM;
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE, "PUT %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host, strlen(ctx->data), ctx->content_type);
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE, "PUT %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host);
                //TODO add len > KHTTP_REQ_SIZE handle
            }
            free(base64);
            base64 = NULL;
        }else{
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE, "PUT %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host, strlen(ctx->data), ctx->content_type);
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE, "PUT %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host);
            }
        }
    }else if(ctx->method == KHTTP_DELETE){
        if(ctx->auth_type == KHTTP_AUTH_BASIC){
            len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s", ctx->username, ctx->password);
            size_t base64_len;
            char *base64 = khttp_base64_encode((unsigned char *) resp_str, len, &base64_len);
            if(!base64) return -KHTTP_ERR_OOM;
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE, "DELETE %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host, strlen(ctx->data), ctx->content_type);
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE, "DELETE %s HTTP/1.1\r\n"
                    "Authorization: Basic %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "\r\n", ctx->path, base64 ,KHTTP_USER_AGENT, ctx->host);
                //TODO add len > KHTTP_REQ_SIZE handle
            }
            free(base64);
            base64 = NULL;
        }else{
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE, "DELETE %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host, strlen(ctx->data), ctx->content_type);
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE, "DELETE %s HTTP/1.1\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s\r\n"
                    "Accept: */*\r\n"
                    "\r\n", ctx->path, KHTTP_USER_AGENT, ctx->host);
            }
        }
    }else{
        //TODO add DELETE and UPDATE?
    }
    if(req){
        khttp_dump_message_flow(req, len, 0);
        if(ctx->send(ctx, req, len, KHTTP_SEND_TIMEO) != KHTTP_ERR_OK){
            khttp_error("khttp request send failure\n");
        }
    }
    if(ctx->data){
        khttp_dump_message_flow(ctx->data, len, 0);
        if(ctx->send(ctx, ctx->data, strlen(ctx->data), KHTTP_SEND_TIMEO) != KHTTP_ERR_OK){
            khttp_error("khttp request send failure\n");
        }
    }
    free(req);
    return 0;
}

static int khttp_send_form(khttp_ctx *ctx)
{
    if(ctx->form){
        //khttp_debug("length: %lu\n%s",ctx->form_len, ctx->form);
        if(ctx->send(ctx, ctx->form, ctx->form_len, KHTTP_SEND_TIMEO) != KHTTP_ERR_OK){
            khttp_error("khttp request send failure\n");
        }
        char buf[47];
        memset(buf, 0, 47);
        snprintf(buf, 47,"--------------------------%s--\r\n", ctx->boundary);
        if(ctx->send(ctx, buf, 46, KHTTP_SEND_TIMEO) != KHTTP_ERR_OK){
            khttp_error("khttp request send failure\n");
        }
    }
    return -KHTTP_ERR_OK;
}

static int khttp_send_http_auth(khttp_ctx *ctx)
{
    char ha1[KHTTP_NONCE_LEN];
    char ha2[KHTTP_NONCE_LEN];
    char resp_str[KHTTP_RESP_LEN];
    char response[KHTTP_NONCE_LEN];
    char cnonce[KHTTP_CNONCE_LEN];
    char *req = malloc(KHTTP_REQ_SIZE);
    if(!req) return -KHTTP_ERR_OOM;
    char *cnonce_b64 = NULL;
    char path[KHTTP_PATH_LEN + 8];
    int len = 0;
    if (ctx->auth_type == KHTTP_AUTH_DIGEST){
        //HA1
        len = snprintf(resp_str, KHTTP_CNONCE_LEN, "%s:%s:%s", ctx->username, ctx->realm, ctx->password);
        memset(ha1, 0, KHTTP_NONCE_LEN);
        khttp_md5sum(resp_str, len, ha1);
        //HA2
        len = snprintf(path, KHTTP_PATH_LEN + 8, "%s:%s", khttp_type2str(ctx->method), ctx->path);
        memset(ha2, 0, KHTTP_NONCE_LEN);
        khttp_md5sum(path, len, ha2);
        //cnonce
        //TODO add random rule generate cnonce
        khttp_md5sum(cnonce, strlen(cnonce), cnonce);
        size_t cnonce_b64_len;
        cnonce_b64 = khttp_base64_encode((unsigned char *) cnonce, 32, &cnonce_b64_len);
        //response
        if(strcmp(ctx->qop, "auth") == 0){
            //FIXME dynamic generate nonceCount "00000001"
            len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s:%s:%s:%s:%s", ha1, ctx->nonce, "00000001", cnonce_b64, ctx->qop, ha2);
            khttp_md5sum(resp_str, len, response);
        }else{
            len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s:%s", ha1, ctx->nonce, ha2);
            khttp_md5sum(resp_str, len, response);
        }
    }else if(ctx->auth_type == KHTTP_AUTH_BASIC){
        len = snprintf(resp_str, KHTTP_RESP_LEN, "%s:%s", ctx->username, ctx->password);
        size_t cnonce_b64_len;
        cnonce_b64 = khttp_base64_encode((unsigned char *) resp_str, len, &cnonce_b64_len);
    }
    if(ctx->method == KHTTP_GET) {
        if(ctx->auth_type == KHTTP_AUTH_DIGEST){//Digest auth
            len = snprintf(req, KHTTP_REQ_SIZE,
                "GET %s HTTP/1.1\r\n"
                "Authorization: %s username=\"%s\", realm=\"%s\", "
                "nonce=\"%s\", uri=\"%s\", "
                "cnonce=\"%s\", nc=00000001, qop=%s, "
                "response=\"%s\"\r\n"
                "User-Agent: %s\r\n"
                "Host: %s:%d\r\n"
                "Accept: */*\r\n\r\n",
                ctx->path,
                khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                ctx->nonce, ctx->path,
                cnonce_b64, ctx->qop,
                response,
                KHTTP_USER_AGENT,
                ctx->host, ctx->port
                );
        }else{//Basic auth
            len = snprintf(req, KHTTP_REQ_SIZE,
                "GET %s HTTP/1.1\r\n"
                "Authorization: %s %s\r\n"
                "User-Agent: %s\r\n"
                "Host: %s:%d\r\n"
                "Accept: */*\r\n\r\n",
                ctx->path,
                khttp_auth2str(ctx->auth_type), cnonce_b64,
                KHTTP_USER_AGENT,
                ctx->host, ctx->port
                );
        }
    }else if(ctx->method == KHTTP_POST){
        if(ctx->auth_type == KHTTP_AUTH_DIGEST){//Digest auth
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "POST %s HTTP/1.1\r\n"
                    "Authorization: %s username=\"%s\", realm=\"%s\", "
                    "nonce=\"%s\", uri=\"%s\", "
                    "cnonce=\"%s\", nc=00000001, qop=%s, "
                    "response=\"%s\"\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                    ctx->nonce, ctx->path,
                    cnonce_b64, ctx->qop,
                    response,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port,
                    strlen(ctx->data),
                    ctx->content_type
                    );
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "POST %s HTTP/1.1\r\n"
                    "Authorization: %s username=\"%s\", realm=\"%s\", "
                    "nonce=\"%s\", uri=\"%s\", "
                    "cnonce=\"%s\", nc=00000001, qop=%s, "
                    "response=\"%s\"\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                    ctx->nonce, ctx->path,
                    cnonce_b64, ctx->qop,
                    response,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port
                    );
            }
        }else{//Basic auth
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "POST %s HTTP/1.1\r\n"
                    "Authorization: %s %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), cnonce_b64,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port,
                    strlen(ctx->data),
                    ctx->content_type
                    );
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "POST %s HTTP/1.1\r\n"
                    "Authorization: %s %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), cnonce_b64,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port
                    );
            }
        }
    }else if(ctx->method == KHTTP_PUT){
        if(ctx->auth_type == KHTTP_AUTH_DIGEST){//Digest auth
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "PUT %s HTTP/1.1\r\n"
                    "Authorization: %s username=\"%s\", realm=\"%s\", "
                    "nonce=\"%s\", uri=\"%s\", "
                    "cnonce=\"%s\", nc=00000001, qop=%s, "
                    "response=\"%s\"\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                    ctx->nonce, ctx->path,
                    cnonce_b64, ctx->qop,
                    response,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port,
                    strlen(ctx->data),
                    ctx->content_type
                    );
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "PUT %s HTTP/1.1\r\n"
                    "Authorization: %s username=\"%s\", realm=\"%s\", "
                    "nonce=\"%s\", uri=\"%s\", "
                    "cnonce=\"%s\", nc=00000001, qop=%s, "
                    "response=\"%s\"\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                    ctx->nonce, ctx->path,
                    cnonce_b64, ctx->qop,
                    response,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port
                    );
            }
        }else{//Basic auth
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "PUT %s HTTP/1.1\r\n"
                    "Authorization: %s %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), cnonce_b64,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port,
                    strlen(ctx->data),
                    ctx->content_type
                    );
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "PUT %s HTTP/1.1\r\n"
                    "Authorization: %s %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), cnonce_b64,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port
                    );
            }
        }
    }else if(ctx->method == KHTTP_DELETE){
        if(ctx->auth_type == KHTTP_AUTH_DIGEST){//Digest auth
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "DELETE %s HTTP/1.1\r\n"
                    "Authorization: %s username=\"%s\", realm=\"%s\", "
                    "nonce=\"%s\", uri=\"%s\", "
                    "cnonce=\"%s\", nc=00000001, qop=%s, "
                    "response=\"%s\"\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                    ctx->nonce, ctx->path,
                    cnonce_b64, ctx->qop,
                    response,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port,
                    strlen(ctx->data),
                    ctx->content_type
                    );
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "DELETE %s HTTP/1.1\r\n"
                    "Authorization: %s username=\"%s\", realm=\"%s\", "
                    "nonce=\"%s\", uri=\"%s\", "
                    "cnonce=\"%s\", nc=00000001, qop=%s, "
                    "response=\"%s\"\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), ctx->username, ctx->realm,
                    ctx->nonce, ctx->path,
                    cnonce_b64, ctx->qop,
                    response,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port
                    );
            }
        }else{//Basic auth
            if(ctx->data){
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "DELETE %s HTTP/1.1\r\n"
                    "Authorization: %s %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type:%s\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), cnonce_b64,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port,
                    strlen(ctx->data),
                    ctx->content_type
                    );
            }else{
                len = snprintf(req, KHTTP_REQ_SIZE,
                    "DELETE %s HTTP/1.1\r\n"
                    "Authorization: %s %s\r\n"
                    "User-Agent: %s\r\n"
                    "Host: %s:%d\r\n"
                    "Accept: */*\r\n"
                    "\r\n",
                    ctx->path,
                    khttp_auth2str(ctx->auth_type), cnonce_b64,
                    KHTTP_USER_AGENT,
                    ctx->host, ctx->port
                    );
            }
        }
    }else{
    }
    khttp_dump_message_flow(req, len, 0);
    if(ctx->send(ctx, req, len, KHTTP_SEND_TIMEO) != KHTTP_ERR_OK){
        khttp_error("khttp request send failure\n");
    }
    if(ctx->data){
        khttp_dump_message_flow(ctx->data, len, 0);
        if(ctx->send(ctx, ctx->data, strlen(ctx->data), KHTTP_SEND_TIMEO) != KHTTP_ERR_OK){
            khttp_error("khttp request send failure\n");
        }
    }
    if(cnonce_b64) free(cnonce_b64);
    if(req) free(req);
    return 0;
}

static int khttp_recv_http_resp(khttp_ctx *ctx)
{
    char buf[KHTTP_NETWORK_BUF];
    memset(buf, 0, KHTTP_NETWORK_BUF);
    int len = 0;
    char *data = NULL;
    // Pass context to http parser data pointer
    ctx->hp.data = ctx;
    int total = 0;
    for(;;) {
        len = ctx->recv(ctx, buf, KHTTP_NETWORK_BUF, KHTTP_RECV_TIMEO);
        if(len < 0) {
            return -KHTTP_ERR_RECV;
        }
        if(len == 0) return -KHTTP_ERR_DISCONN;
        data = realloc(data, total + len + 1);
        memcpy(data + total, buf, len);
        total += len;
        http_parser_init(&ctx->hp, HTTP_RESPONSE);
        ctx->body_len = 0;//Reset body length until parse finish.
        if(strncmp(data, "HTTP/1.1 100 Continue", 21) == 0){
            ctx->cont = 1;
            // char *end = strstr(data, "\r\n\r\n");
            //khttp_debug("len: %d\n%s\n", len, data);
            if(len == 25){//Only get 100 Continue
                ctx->hp.status_code = 100;
                //khttp_debug("Only get 100 continue\n");
                goto end;
            }else if(len > 25){
                ctx->cont = 1;//Get 100 Continue and others
                total = total - 25;
                memmove(data, data + 25, len - 25);
            }
        }
        //khttp_info("Parse:\n%s\n", data);
        http_parser_execute(&ctx->hp, &http_parser_cb, data, total);
        if(ctx->done == 1){
            break;
        }
    }
    http_parser_init(&ctx->hp, HTTP_RESPONSE);
    // Malloc memory for body
    ctx->body = malloc(ctx->body_len + 1);
    if(!ctx->body){
        return -KHTTP_ERR_OOM;
    }
    //khttp_debug("malloc %zu byte for body\n", ctx->body_len);
    memset(ctx->body, 0, ctx->body_len + 1);
    //Set body length to 0 before parse
    ctx->body_len = 0;
    if(ctx->body == NULL) return -KHTTP_ERR_OOM;
    http_parser_execute(&ctx->hp, &http_parser_cb, data, total);
    //khttp_debug("status_code %d\n", ctx->hp.status_code);
    //khttp_debug("body:\n%s\n", ctx->body);
    //FIXME why mark end of data will crash. WTF
    data[total] = 0;
    khttp_dump_message_flow(data, total, 0);
    // Free receive buffer
end:
    free(data);
    return KHTTP_ERR_OK;
}

int khttp_perform(khttp_ctx *ctx) {
    int result = KHTTP_ERR_OK;

    // Get IP address from DNS server
    struct addrinfo * servinfo = NULL;     // need to be free
    struct addrinfo hints = {
        .ai_socktype = SOCK_STREAM,
        .ai_family   = AF_INET
    };
    char port[16] = {};
    sprintf(port, "%d", ctx->port);
    int ret = getaddrinfo(ctx->host, port, &hints, &servinfo);

#if !defined(__ANDROID__) && !defined(__MAC__) && !defined(__IOS__)
    // do res_init(), and do getaddrinfo() again
    if (ret != 0) {
        khttp_info("reload '/etc/resolv.conf' ...\n");
        res_init();
        ret = getaddrinfo(ctx->host, port, &hints, &servinfo);
    }
#endif

    // check getaddrinfo return value
    if (ret != 0) {
        khttp_error("khttp DNS lookup failure. getaddrinfo: %s (%d)\n", gai_strerror(ret), ret);
        result = -KHTTP_ERR_DNS;
        goto end;
    }

    // setup serv_addr
    ctx->serv_addr.sin_addr = ((struct sockaddr_in *)servinfo->ai_addr)->sin_addr;
    ctx->serv_addr.sin_port = htons(ctx->port);
    // char addrstr[100];
    // inet_ntop (servinfo->ai_family, &ctx->serv_addr.sin_addr, addrstr, 100);
    // khttp_debug("IP:%s\n", addrstr);

    // create socket
    ctx->fd = khttp_socket_create();
    if (ctx->fd < 1) {
        khttp_error("khttp socket create error\n");
        result = -KHTTP_ERR_SOCK;
        goto end;
    }

    // get socket status flag
    int flags = fcntl(ctx->fd, F_GETFL);
    if (flags == -1) {
        khttp_error("fcntl F_GETFL failed, errno = %s (%d)\n", strerror(errno), errno);
        ret = -KHTTP_ERR_SOCK;
        goto end;
    }

    // set non-blocking flag
    ret = fcntl(ctx->fd, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        khttp_error("fcntl F_SETFL failed, errno = %s (%d)\n", strerror(errno), errno);
        result = -KHTTP_ERR_SOCK;
        goto end;
    }

    // connect (non-blocking)
    ret = connect(ctx->fd, servinfo->ai_addr, servinfo->ai_addrlen);
    if (ret == -1 && errno != EINPROGRESS) {
        khttp_error("connect failed, errno = %s (%d)\n", strerror(errno), errno);
        result = -KHTTP_ERR_CONNECT;
        goto end;
    }

    // add ctx->fd to fdset
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(ctx->fd, &fdset);
    struct timeval tv = {
        .tv_sec = 5         // select timeout 5 seconds
    };

    // select ctx->fd
    ret = select(ctx->fd + 1, NULL, &fdset, NULL, &tv);
    if (ret == 0) {
        khttp_error("connection timeout\n");
        result = -KHTTP_ERR_TIMEOUT;
        goto end;
    } else if (ret < 0) {
        khttp_error("select error, errno = %s (%d)\n", strerror(errno), errno);
        result = -KHTTP_ERR_CONNECT;
        goto end;
    } else {
        // ret > 0
        int so_error;
        socklen_t len = sizeof(int);
        ret = getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (ret != 0) {
            khttp_error("getsockopt SOL_SOCKET failed, errno = %s (%d)\n", strerror(errno), errno);
            result = -KHTTP_ERR_CONNECT;
            goto end;
        }

        if (so_error != 0) {
            khttp_error("connect failed, so_error = %s (%d)\n", strerror(so_error), so_error);
            result = -KHTTP_ERR_CONNECT;
            goto end;
        }
    }

    // connect success, set back to original flags
    ret = fcntl(ctx->fd, F_SETFL, flags);
    if (ret == -1) {
        khttp_error("fcntl F_SETFL failed, errno = %s (%d)\n", strerror(errno), errno);
        result = -KHTTP_ERR_SOCK;
        goto end;
    }
    // khttp_debug("khttp connect to server successfully\n");

    // setup SSL
    if (ctx->proto == KHTTP_HTTPS) {
#ifdef OPENSSL
        if (khttp_ssl_setup(ctx) != KHTTP_ERR_OK) {
            khttp_error("khttp ssl setup failure\n");
            result = -KHTTP_ERR_SSL;
            goto end;
        }
        // khttp_debug("khttp setup ssl connection successfully\n");
#else
        result = -KHTTP_ERR_NOT_SUPP;
        goto end;
#endif
    }

    int count = 0;
    for (;;) {
        if (ctx->hp.status_code == 401) {
            // khttp_debug("Send HTTP authentication response\n");
            // FIXME change to khttp_send_http_auth
            if ((ret = khttp_send_http_auth(ctx)) != 0) {
                khttp_error("khttp send HTTP authentication response failure %d\n", ret);
                break;
            }
            // FIXME
            ctx->hp.status_code = 0;
        } else if (ctx->hp.status_code == 200) {
            if (ctx->cont == 1 && ctx->form != NULL) {
                khttp_send_form(ctx);
                ctx->cont = 0;      // Clean continue flag for next read
                goto end;           // Send data then end
            }
        } else if (ctx->hp.status_code == 100) {
            if (ctx->cont == 1 && ctx->form != NULL) {
                khttp_send_form(ctx);
                ctx->cont = 0;      // Clean continue flag for next read
            }
            // TODO What's next if no form or data to send
        } else {
            // khttp_debug("Send HTTP request\n");
            if ((ret = khttp_send_http_req(ctx)) != 0) {
                khttp_error("khttp send HTTP request failure %d\n", ret);
                break;
            }
        }

        // free all header before recv data
        khttp_free_header(ctx);
        khttp_free_body(ctx);
        if ((ret = khttp_recv_http_resp(ctx)) != 0) {
            khttp_error("khttp recv HTTP response failure %d\n", ret);
            result = ret;
            goto end;
        }
        // khttp_debug("receive HTTP response success\n");

        switch(ctx->hp.status_code) {
            case 401: {
                char * str = khttp_find_header(ctx, "WWW-Authenticate");
                if (khttp_parse_auth(ctx, str) != 0) {
                    khttp_error("khttp parse auth string failure\n");
                    goto end;
                }
                if (count == 1 || (count == 0 && ctx->auth_type == KHTTP_AUTH_BASIC)) {
                    goto end;
                }
                break;
            }

            case 200:
                // khttp_info("GOT 200 OK count:%d\n", count);
                if (ctx->cont == 1 && count == 0) {
                    // khttp_info("Got 200 OK before send post data/form\n");
                    break;
                }
                goto end;

            case 100:
                // khttp_info("GOT 100 Continue\n");
                if (ctx->cont == 1 && count == 0) {
                    break;
                }
                // khttp_send_form(ctx);
                // Send form data...
                break;

            default:
                goto end;
        }

        // Session count
        count ++;
        // khttp_debug("recv http data\n");
        // khttp_debug("end\n%s\n", ctx->body);
        // printf("end\n%s\n", (char *)ctx->body);
    }

end:
    if (servinfo != NULL) freeaddrinfo(servinfo);
    return result;
}

const char * khttp_strerror(int err) {
    // negative
    switch (-err) {
        case KHTTP_ERR_OK:          return "KHTTP_ERR_OK";
        case KHTTP_ERR_TIMEOUT:     return "KHTTP_ERR_TIMEOUT";
        case KHTTP_ERR_DNS:         return "KHTTP_ERR_DNS";
        case KHTTP_ERR_SOCK:        return "KHTTP_ERR_SOCK";
        case KHTTP_ERR_SSL:         return "KHTTP_ERR_SSL";
        case KHTTP_ERR_OOM:         return "KHTTP_ERR_OOM";
        case KHTTP_ERR_SEND:        return "KHTTP_ERR_SEND";
        case KHTTP_ERR_RECV:        return "KHTTP_ERR_RECV";
        case KHTTP_ERR_PARAM:       return "KHTTP_ERR_PARAM";
        case KHTTP_ERR_CONNECT:     return "KHTTP_ERR_CONNECT";
        case KHTTP_ERR_DISCONN:     return "KHTTP_ERR_DISCONN";
        case KHTTP_ERR_NO_FD:       return "KHTTP_ERR_NO_FD";
        case KHTTP_ERR_NOT_SUPP:    return "KHTTP_ERR_NOT_SUPP";
        case KHTTP_ERR_NO_FILE:     return "KHTTP_ERR_NO_FILE";
        case KHTTP_ERR_FILE_READ:   return "KHTTP_ERR_FILE_READ";
        default:
            khttp_error("unknown error code %d\n", err);
            return "KHTTP_ERR_UNKNOWN";
    }
}

static void khttp_log(int level, int line, const char * func, const char * format, ...) {
    if (khttp_log_callback == NULL) {
        return;
    }

    char message[KHTTP_MESSAGE_MAX_LEN] = {0};

    // create message by va_list
    va_list args;
    va_start(args, format);
    vsnprintf(message, KHTTP_MESSAGE_MAX_LEN, format, args);
    va_end(args);

    // invoke log callback function
    khttp_log_callback(__FILE__, "KHTTP", level, line, func, message);
}

void khttp_set_log_callback(void (* callback)(const char * file, const char * tag, int level, int line, const char * func, const char * message)) {
    khttp_log_callback = callback;
}
