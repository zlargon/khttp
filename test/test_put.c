#include "khttp.h"
#include "log.h"

void test_put()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/put");
    khttp_set_method(ctx, KHTTP_PUT);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_put_digest()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/putdigest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_PUT);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_put_basic()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/putbasic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_set_post_data(ctx, "name=kevin&email=kaija.chang@gmail.com");
    khttp_set_method(ctx, KHTTP_PUT);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

int main()
{
    test_put();
    test_put_digest();
    test_put_basic();
    return 0;
}
