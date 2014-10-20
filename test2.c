#include "khttp.h"
#include "log.h"
#define a() aa(__func__, __LINE__)

void aa(const char *func, int line)
{
    printf("who call me %s:%d\n", func, line);
}
void test_url_parse()
{
    char buf[] = "www.google.com:900";
    struct http_parser_url u;
    LOG_INFO("Test start\n");
    khttp_ctx *ctx = khttp_new();
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa");
    //khttp_set_uri(ctx, "http://www.google.com:9876/afdlsa");
    //khttp_set_uri(ctx, "https://www.google.com/afdlsa");
    //khttp_set_uri(ctx, "https://www.google.com:98768/afdlsa");
    //khttp_set_uri(ctx, "https://www.google.com/");
    //khttp_set_uri(ctx, "https://www.google.com");
    khttp_set_uri(ctx, "http://www.google.com");
    //khttp_set_uri(ctx, "https://www.google.com:9876/afdlsa/");
    khttp_perform(ctx);
}
int main()
{
    test_url_parse();
}
