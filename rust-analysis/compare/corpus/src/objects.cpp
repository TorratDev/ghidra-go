// Hosted C++ corpus program: vtables, exceptions, templates, static init.
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <string>

struct Shape {
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual const char *name() const { return "shape"; }
};

struct Rect : Shape {
    double w, h;
    Rect(double w, double h) : w(w), h(h) {}
    double area() const override { return w * h; }
    const char *name() const override { return "rect"; }
};

struct Circle : Shape {
    double r;
    explicit Circle(double r) : r(r) {}
    double area() const override { return 3.14159 * r * r; }
};

template <typename T> __attribute__((noinline)) T maxof(const std::vector<T> &v) {
    if (v.empty()) throw std::runtime_error("empty");
    T m = v[0];
    for (const T &x : v) if (x > m) m = x;
    return m;
}

static std::string banner = "objects";

int main(int argc, char **) {
    std::vector<Shape *> shapes{new Rect(2, 3), new Circle(argc)};
    std::vector<double> areas;
    for (Shape *s : shapes) {
        std::printf("%s %f\n", s->name(), s->area());
        areas.push_back(s->area());
    }
    try {
        std::printf("%s max %f\n", banner.c_str(), maxof(areas));
        std::vector<int> none;
        maxof(none);
    } catch (const std::exception &e) {
        std::printf("caught %s\n", e.what());
    }
    for (Shape *s : shapes) delete s;
    return 0;
}
