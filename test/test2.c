#include "khttp.h"
#include "log.h"
#define a() aa(__func__, __LINE__)

void aa(const char *func, int line)
{
    printf("who call me %s:%d\n", func, line);
}
void test_url_parse()
{
    //LOG_INFO("Test start\n");
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://www.inside.com.tw");
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa/");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_digest()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/alive");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa/");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_digest_fail()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/alive");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_DIGEST);
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa/");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_but_digest()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/alive");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa/");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_but_digest_fail()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/alive");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa/");
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_fail()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/basic");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}
void test_basic()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "http://localhost:8888/basic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

int main()
{
        //test_url_parse();
    while(1){
        //test_digest();
        //test_digest_fail();
        //test_basic();
        //test_basic_fail();
        //test_basic_but_digest();
        test_basic_but_digest_fail();
    }
}
