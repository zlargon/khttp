#include "khttp.h"
#include "log.h"
#include <pthread.h>

#define MAX_THREAD 4
void *test_get_digest()
{
    while(1){
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_method(ctx, KHTTP_GET);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
    }
}

void *test_get_digest_https()
{
    while(1){
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_method(ctx, KHTTP_GET);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
    }
}

void log_callback(const char * file, const char * tag, int level, int line, const char * func, const char * message) {
    if (level == KHTTP_LOG_DEBUG)   return log_print(DEBUG, file, line, message);
    if (level == KHTTP_LOG_INFO)    return log_print(INFO,  file, line, message);
    if (level == KHTTP_LOG_WARN)    return log_print(WARN,  file, line, message);
    if (level == KHTTP_LOG_ERROR)   return log_print(ERROR, file, line, message);
}

int main()
{
    khttp_set_log_callback(log_callback);
    int i = 0;
#if 0
#else
    pthread_t pt[MAX_THREAD];
    for(i=0;i<MAX_THREAD;i++){
        pthread_create(&pt[i], NULL, test_get_digest, NULL);
    }
    pthread_t pts[MAX_THREAD];
    for(i=0;i<MAX_THREAD;i++){
        pthread_create(&pts[i], NULL, test_get_digest_https, NULL);
    }
#endif
    while(1){
        sleep(1);
    }
    return 0;
}
