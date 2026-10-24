/* Freestanding corpus program for cross targets (no libc): built for i386,
 * AArch64 ELF and x86-64 PE. Entry point is `_start`. */
typedef unsigned long uptr;

volatile int sink;
static const char message[] = "freestanding corpus";
int table_data[16] = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987 };

__attribute__((noinline)) static int add(int a, int b) { return a + b; }
__attribute__((noinline)) static int mul(int a, int b) { return a * b; }
__attribute__((noinline)) static int sub(int a, int b) { return a - b; }

typedef int (*binop)(int, int);
static binop binops[] = { add, mul, sub };

__attribute__((noinline, noreturn)) void halt_forever(void) {
    for (;;) sink = 0;
}

__attribute__((noinline)) int dispatch(int which, int a, int b) {
    switch (which) {
    case 0: return add(a, b);
    case 1: return mul(a, b) + 1;
    case 2: return sub(a, b) - 2;
    case 3: return a << b;
    case 4: return a >> b;
    case 5: return a ^ b;
    case 6: return a | b;
    case 7: return a & b;
    default: return 0;
    }
}

__attribute__((noinline)) uptr string_length(const char *s) {
    uptr n = 0;
    while (s[n]) n++;
    return n;
}

__attribute__((noinline)) int fold(int n) {
    int acc = 0;
    for (int i = 0; i < n && i < 16; i++) acc = binops[i % 3](acc, table_data[i]);
    return acc;
}

__attribute__((noinline)) int recurse(int n) { return n <= 1 ? 1 : n * recurse(n - 1); }

void _start(void) {
    int r = dispatch(sink & 7, 5, 3);
    r += (int)string_length(message);
    r += fold(sink + 10);
    r += recurse(5);
    sink = r;
    halt_forever();
}

/* Some PE toolchains look for these symbols. */
void mainCRTStartup(void) { _start(); }
