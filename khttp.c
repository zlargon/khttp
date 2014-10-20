#include "khttp.h"
#include "log.h"
#include <errno.h>

int khttp_socket_nonblock(int fd, int enable);
int khttp_socket_reuseaddr(int fd, int enable);
int http_socket_sendtimeout(int fd, int timeout);
int http_socket_recvtimeout(int fd, int timeout);

struct {
    char text[8];
}method_type[]={
    {"GET"},
    {"POST"},
    {"UPDATE"},
    {"DELETE"}
};
static char *khttp_type2str(int type)
{
    return method_type[type].text;
}

khttp_ctx *khttp_new()
{
    khttp_ctx *ctx = malloc(sizeof(khttp_ctx));
    if(!ctx){
        LOG_ERROR("khttp context create failure out of memory\n");
    }
    LOG_DEBUG("khttp context created\n");
    memset(ctx, 0, sizeof(khttp_ctx));
    return ctx;
}

void khttp_destroy(khttp_ctx *ctx)
{
    if(ctx->ssl){
        SSL_set_shutdown(ctx->ssl, 2);
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
    }
    if(ctx){
        free(ctx);
    }
}

int khttp_socket_create()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        LOG_ERROR("khttp socket create failure %d(%s)\n", errno, strerror(errno));
        return fd;
    }
    //Default enable nonblock / reuseaddr and set send / recv timeout
    khttp_socket_nonblock(fd, 1);
    khttp_socket_reuseaddr(fd, 1);
    http_socket_sendtimeout(fd, KHTTP_SEND_TIMEO);
    http_socket_recvtimeout(fd, KHTTP_RECV_TIMEO);
    return fd;
}

int khttp_socket_nonblock(int fd, int enable)
{
    unsigned long on = enable;
    int ret = ioctl(fd, FIONBIO, &on);
    if(ret != 0){
        LOG_WARN("khttp set socket nonblock failure %d(%s)\n", errno, strerror(errno));
    }
    return ret;
}

int khttp_socket_reuseaddr(int fd, int enable)
{
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable));
    if(ret != 0){
        LOG_WARN("khttp set socket reuseaddr failure %d(%s)\n", errno, strerror(errno));
    }
    return ret;
}

int http_socket_sendtimeout(int fd, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    int ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    if(ret != 0){
        LOG_WARN("khttp set socket send timeout failure %d(%s)\n", errno, strerror(errno));
    }
    return ret;
}

int http_socket_recvtimeout(int fd, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    int ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    if(ret != 0){
        LOG_WARN("khttp set socket recv timeout failure %d(%s)\n", errno, strerror(errno));
    }
    return ret;
}

int khttp_md5sum(char *input, int len, char *out)
{
    int ret = 0, i = 0;
    MD5_CTX ctx;
    char buf[3] = {'\0'};
    unsigned char md5[MD5_DIGEST_LENGTH];
    if(input == NULL || len < 1 || out == NULL)
        return -1;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, len);
    MD5_Final(md5, &ctx);
    out[0] = '\0';
    for(i=0;i<MD5_DIGEST_LENGTH;i++)
    {
        sprintf(buf, "%02x", md5[i]);
        strcat(out, buf);
    }
    //LOG_DEBUG("MD5:[%s]\n", out);
    return ret;
}

int khttp_set_method(khttp_ctx *ctx, int method)
{
    if(method < KHTTP_GET || method > KHTTP_DELETE){
        LOG_ERROR("khttp set method parameter out of range\n");
        return -KHTTP_ERR_PARAM;
    }
    ctx->method = method;
    return KHTTP_ERR_OK;
}
void khttp_copy_host(char *in, char *out)
{
    int i = 0;
    for(i=0 ; i<strlen(in) ; i++) {
        if(in[i] == ':' || in[i] == '/' || in[i] == '\0') break;
        out[i] = in[i];
    }
}

void khttp_dump_uri(khttp_ctx *ctx)
{
    printf("======================\n");
    printf("host: %s\n", ctx->host);
    printf("port: %d\n", ctx->port);
    printf("path: %s\n", ctx->path);
}


int http_send(khttp_ctx *ctx, void *buf, int len, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000 )  * 1000;
    if(ctx->fd < 0) {
        return -KHTTP_ERR_NO_FD;
    }
    int sent = 0;
    do {
        fd_set fs;
        FD_ZERO(&fs);
        FD_SET(ctx->fd, &fs);
        int ret = select(ctx->fd +1, NULL, &fs, NULL, &tv);
        if(ret > 0){
            ret = send(ctx->fd, buf + sent, len - sent, 0);
        }

    }while(sent < len);
}

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
        //TODO Send default send / recv callback
    } else if(strncasecmp(uri, "http://", 7) == 0) {
        ctx->proto = KHTTP_HTTP;
        host = head + 7;
        //TODO Send default send / recv callback
    } else {
        ctx->proto = KHTTP_HTTP;
        host = head;
    }
    if((path = strchr(host, '/'))!= NULL) {
        strncpy(ctx->path, path, KHTTP_PATH_LEN);
    } else {
        strcpy(ctx->path, "*");
    }
    if((port = strchr(host, ':'))!= NULL) {
        ctx->port = atoi(port + 1);
        if(ctx->port < 1 || ctx->port > 65535){
            LOG_ERROR("khttp set port out of range: %d! use default port\n", ctx->port);
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

static int ssl_ca_verify_cb(int ok, X509_STORE_CTX *store)
{
    int depth, err;
    X509 *cert = NULL;
    //return 0;
    return ok;
}


int khttp_ssl_setup(khttp_ctx *ctx)
{
    SSL_load_error_strings();
    if(SSL_library_init() != 1) {
        LOG_ERROR("SSL library init failure\n");
        return -KHTTP_ERR_SSL;
    }
    // try SSLv3
    if( (ctx->ssl_ctx = SSL_CTX_new(SSLv3_method())) == NULL) {
        // try TLSv1
        if( (ctx->ssl_ctx = SSL_CTX_new(SSLv3_method())) == NULL ) {
            return -KHTTP_ERR_SSL;
        }
    }
    // Pass server auth
    if(ctx->pass_serv_auth){
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }else{
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, ssl_ca_verify_cb);
        SSL_CTX_set_verify_depth(ctx->ssl_ctx, KHTTP_SSL_DEPTH);
        if(SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->cert_path, NULL) != 1){
            LOG_ERROR("khttp not able to load certificate on path: %s\n", ctx->cert_path);
        }
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx->ssl_ctx, ctx->key_pass);
    if(SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, ctx->cert_path) == 1) {
        LOG_DEBUG("khttp load certificate success\n");
    }
    if(SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->key_path, SSL_FILETYPE_PEM) == 1) {
        LOG_DEBUG("khttp load private key success\n");
    }
    if(SSL_CTX_check_private_key(ctx->ssl_ctx) == 1) {
        LOG_DEBUG("khttp check private key success\n");
    }else{
        //TODO
    }
    if((ctx->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
        LOG_ERROR("create SSL failure\n");
        return -KHTTP_ERR_SSL;
    }
    if(SSL_set_fd(ctx->ssl, ctx->fd) != 1) {
        LOG_ERROR("set SSL fd failure\n");
        return -KHTTP_ERR_SSL;
    }
    if(SSL_connect(ctx->ssl) != 1) {
        return -KHTTP_ERR_SSL;//TODO
    }
    LOG_DEBUG("Connect to SSL server success\n");
    return 0;
}

int khttp_perform(khttp_ctx *ctx)
{
    struct addrinfo hints;
    struct addrinfo *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    int res = 0;
    int ret = KHTTP_ERR_OK;
    if((res = getaddrinfo(ctx->host, NULL, &hints, &result)) != 0){
        LOG_ERROR("khttp DNS lookup failure. getaddrinfo: %s\n", gai_strerror(res));
        ret = -KHTTP_ERR_DNS;
    }
    ctx->serv_addr.sin_addr = ((struct sockaddr_in *) (result->ai_addr))->sin_addr;
    ctx->serv_addr.sin_port = htons(ctx->port);
    freeaddrinfo(result);
    ctx->fd = khttp_socket_create();
    if(ctx->fd < 1){
        LOG_ERROR("khttp socket create error\n");
        ret = -KHTTP_ERR_SOCK;
    }
    if(connect(ctx->fd, (struct sockaddr *) &(ctx->serv_addr), sizeof(struct sockaddr))!= 0) {
        LOG_ERROR("khttp connect to server error %d(%s)\n", errno, strerror(errno));
        ret = KHTTP_ERR_CONNECT;
        goto err;
    }
    LOG_DEBUG("khttp connect to server successfully\n");
    for(;;)
    {
        LOG_DEBUG("send http data\n");
        sleep(1);
        LOG_DEBUG("recv http data\n");
        sleep(1);
    }
    return ret;
err:
    return ret;
}
