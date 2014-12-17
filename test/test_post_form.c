#include "khttp.h"
#include "log.h"

void test_post_form()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    khttp_set_method(ctx, KHTTP_POST);
    khttp_set_post_form(ctx, "name", "kevin", KHTTP_FORM_STRING);
    khttp_set_post_form(ctx, "email", "kaija.chang@gmail.com", KHTTP_FORM_STRING);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_post_file()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    khttp_set_post_form(ctx, "file", "test.bin", KHTTP_FORM_FILE);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_post_form_file()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    khttp_set_post_form(ctx, "name", "kevin", KHTTP_FORM_STRING);
    khttp_set_post_form(ctx, "file", "test.bin", KHTTP_FORM_FILE);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_post_form_digest()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post_digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_post_form(ctx, "name", "kevin", KHTTP_FORM_STRING);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

int log_callback(const char * file, const char * tag, const char * level, int line, const char * func, const char * message) {
    if (strcmp(level, "DEBUG") == 0)     log_print(DEBUG, file, line, message);
    else if (strcmp(level, "INFO") == 0) log_print(INFO,  file, line, message);
    else if (strcmp(level, "WARN") == 0) log_print(WARN,  file, line, message);
    else                                 log_print(ERROR, file, line, message);
    return 0;
}

int main()
{
    khttp_set_log_callback(log_callback);
    test_post_form();
    test_post_file();
    test_post_form_file();
    test_post_form_digest();
    return 0;
}
