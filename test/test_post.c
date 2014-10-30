#include "khttp.h"
#include "log.h"

void test_digest()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pdigest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_digest_fail()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pdigest");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_DIGEST);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 401){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_basic_but_digest()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pdigest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_basic_but_digest_fail()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pdigest");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 401){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_basic_fail()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pbasic");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 401){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}
void test_basic()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pbasic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_post_with_data()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    khttp_set_method(ctx, KHTTP_POST);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_basic_with_data()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pbasic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

void test_digest_with_data()
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",__func__);
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/pdigest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    if(ctx->hp.status_code == 200){
        printf("PASS\n");
    }else{
        printf("FAIL");
    }
    khttp_destroy(ctx);
}

int main()
{
    //while(1){
        test_post_with_data();
        test_basic_with_data();
        test_digest_with_data();
        test_digest();
        test_digest_fail();
        test_basic();
        test_basic_fail();
        test_basic_but_digest();
        test_basic_but_digest_fail();
    //}
    return 0;
}
