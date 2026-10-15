/* benign.c — clean sample for necropsy E2E tests */
#include <stdio.h>
#include <string.h>

static const char *greeting = "hello from a harmless program";
static const char *site = "https://example.com/welcome";

int helper_sum(int a, int b) {
    return a + b;
}

int main(int argc, char **argv) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s (%d args)", greeting, argc);
    puts(buf);
    printf("visit %s\n", site);
    printf("sum=%d\n", helper_sum(2, 3));
    return 0;
}
