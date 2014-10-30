#include "khttp.h"
#include "log.h"

void test_post_form()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    khttp_set_method(ctx, KHTTP_POST);
    khttp_set_post_form(ctx, "name", "kevin", KHTTP_FORM_STRING);
    khttp_set_post_form(ctx, "email", "kaija.chang@gmail.com", KHTTP_FORM_STRING);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_post_file()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    //khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_post_form(ctx, "file", "test.bin", KHTTP_FORM_FILE);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_post_form_file()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/post");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    //khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_POST);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

int main()
{
    test_post_form();
    test_post_file();
    //test_post_form_file();
    return 0;
}
