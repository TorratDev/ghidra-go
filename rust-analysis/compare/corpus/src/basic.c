/* Hosted x86-64 corpus program: exercises calls, tail calls, jump tables,
 * function pointers, no-return paths, recursion, globals and strings. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

int counter = 3;
static const char *names[] = { "alpha", "beta", "gamma", "delta", "epsilon" };

__attribute__((noinline)) static int square(int x) { return x * x; }
__attribute__((noinline)) static int cube(int x) { return x * square(x); }
__attribute__((noinline)) static int neg(int x) { return -x; }

typedef int (*op_fn)(int);
static op_fn ops[] = { square, cube, neg };

__attribute__((noinline, noreturn)) static void die(const char *msg) {
    fprintf(stderr, "fatal: %s\n", msg);
    exit(2);
}

__attribute__((noinline)) int classify(int v) {
    switch (v) {
    case 0: return 11;
    case 1: return 23;
    case 2: return 37;
    case 3: return 41;
    case 4: return 59;
    case 5: return 61;
    case 6: return 79;
    case 7: return 83;
    default: return -1;
    }
}

__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

__attribute__((noinline)) int tail(int x) { return cube(x + counter); }

__attribute__((noinline)) int sum(int n, ...) {
    va_list ap;
    int s = 0;
    va_start(ap, n);
    for (int i = 0; i < n; i++) s += va_arg(ap, int);
    va_end(ap);
    return s;
}

__attribute__((noinline)) int checked_div(int a, int b) {
    if (b == 0) die("division by zero");
    return a / b;
}

int main(int argc, char **argv) {
    int v = argc > 1 ? atoi(argv[1]) : 2;
    if (v < 0) abort();
    printf("%s %d %d\n", names[v % 5], classify(v), fib(v + 5));
    printf("%d %d\n", ops[v % 3](v), tail(v));
    printf("%d %zu\n", sum(4, 1, 2, 3, v), strlen(argv[0]));
    counter += checked_div(100, v + 1);
    return counter & 0xff;
}
