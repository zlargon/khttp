#include "khttp.h"
#include "log.h"

void test_del()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/delete");
    khttp_set_method(ctx, KHTTP_DELETE);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_del_digest()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/deletedigest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_DELETE);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_del_basic()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/deletebasic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_DELETE);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

int main()
{
    while(1){
        test_del();
        test_del_digest();
        test_del_basic();
    }
    return 0;
}
