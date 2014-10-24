#include "khttp.h"
#include "log.h"

void test_chunked_encode_v2()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://www.facebook.com/");
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_chunked_encode()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://www.paypal.com/tw/webapps/mpp/home");
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_content_length()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://tw.news.yahoo.com/");
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_digest()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_digest_fail()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_DIGEST);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_but_digest()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_but_digest_fail()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_fail()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/basic");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}
void test_basic()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/basic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_digest_cert()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_DIGEST);
    khttp_ssl_set_cert_key(ctx, "f835dd000010.pem", "f835dd000010.pem", NULL);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_digest_fail_cert()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_DIGEST);
    khttp_ssl_set_cert_key(ctx, "f835dd000010.pem", "f835dd000010.pem", NULL);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_but_digest_cert()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_ssl_set_cert_key(ctx, "f835dd000010.pem", "f835dd000010.pem", NULL);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_but_digest_fail_cert()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/digest");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_ssl_set_cert_key(ctx, "f835dd000010.pem", "f835dd000010.pem", NULL);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

void test_basic_fail_cert()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/basic");
    khttp_set_username_password(ctx, "bob", "secret1", KHTTP_AUTH_BASIC);
    khttp_ssl_set_cert_key(ctx, "f835dd000010.pem", "f835dd000010.pem", NULL);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}
void test_basic_cert()
{
    khttp_ctx *ctx = khttp_new();
    khttp_set_uri(ctx, "https://localhost/basic");
    khttp_set_username_password(ctx, "bob", "secret", KHTTP_AUTH_BASIC);
    khttp_ssl_set_cert_key(ctx, "f835dd000010.pem", "f835dd000010.pem", NULL);
    khttp_ssl_skip_auth(ctx);
    khttp_perform(ctx);
    khttp_destroy(ctx);
}

int main()
{
    //while(1){
        test_chunked_encode();
        test_content_length();
        test_digest();
        test_digest_fail();
        test_basic();
        test_basic_fail();
        test_basic_but_digest();
        test_basic_but_digest_fail();
        test_digest_cert();
        test_digest_fail_cert();
        test_basic_cert();
        test_basic_fail_cert();
        test_basic_but_digest_cert();
        test_basic_but_digest_fail_cert();
    //}
    return 0;
}
