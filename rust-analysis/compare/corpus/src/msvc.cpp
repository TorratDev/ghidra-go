// Freestanding MSVC-ABI C++ corpus DLL (no CRT): exported classes, ctors,
// dtors, virtuals, operators, templates and namespaces produce MSVC-mangled
// export names for the demangler comparison.
#define API __declspec(dllexport)

extern "C" int _fltused = 0;

// No CRT: the deleting destructors need these.
void operator delete(void *) noexcept {}
void operator delete(void *, __SIZE_TYPE__) noexcept {}

namespace geo {

struct API Shape {
    Shape() : id(1) {}
    virtual ~Shape() {}
    virtual int area() const { return 0; }
    virtual const char *name() const { return "shape"; }
    int id;
};

struct API Rect : Shape {
    Rect(int w, int h) : w(w), h(h) {}
    ~Rect() override {}
    int area() const override { return w * h; }
    const char *name() const override { return "rect"; }
    bool operator==(const Rect &o) const { return w == o.w && h == o.h; }
    Rect &operator+=(int d) {
        w += d;
        h += d;
        return *this;
    }
    static int count;
    int w, h;
};

int Rect::count = 0;

namespace detail {
API int scale(int v, int by) { return v * by; }
API unsigned long long widen(unsigned v) { return v; }
} // namespace detail

template <typename T> API T largest(const T *xs, int n) {
    T m = xs[0];
    for (int i = 1; i < n; i++)
        if (xs[i] > m) m = xs[i];
    return m;
}

template API int largest<int>(const int *, int);
template API double largest<double>(const double *, int);

} // namespace geo

API int __cdecl plain_cdecl(int a) { return a + 1; }
API int __stdcall plain_stdcall(int a, int b) { return a - b; }
API int global_counter = 7;
