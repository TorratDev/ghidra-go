//! Freestanding Rust corpus program (no_std, no libc): modules, generics,
//! traits, closures and impls produce Rust-mangled symbols for the
//! demangler comparison. Entry point is `_start`.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

static mut SINK: u64 = 0;

fn sink(v: u64) {
    unsafe { write_volatile(core::ptr::addr_of_mut!(SINK), v) }
}

fn source() -> u64 {
    unsafe { read_volatile(core::ptr::addr_of!(SINK)) }
}

pub mod shapes {
    pub trait Shape {
        fn area(&self) -> u64;
        fn name(&self) -> &'static str {
            "shape"
        }
    }

    pub struct Rect {
        pub w: u64,
        pub h: u64,
    }

    pub struct Square(pub u64);

    impl Shape for Rect {
        #[inline(never)]
        fn area(&self) -> u64 {
            self.w * self.h
        }
        #[inline(never)]
        fn name(&self) -> &'static str {
            "rect"
        }
    }

    impl Shape for Square {
        #[inline(never)]
        fn area(&self) -> u64 {
            self.0 * self.0
        }
    }

    impl Rect {
        #[inline(never)]
        pub fn new(w: u64, h: u64) -> Self {
            Rect { w, h }
        }
    }

    #[inline(never)]
    pub fn total(items: &[&dyn Shape]) -> u64 {
        items.iter().map(|s| s.area()).sum()
    }
}

pub mod math {
    #[inline(never)]
    pub fn largest<T: PartialOrd + Copy>(xs: &[T]) -> T {
        let mut m = xs[0];
        for &x in xs {
            if x > m {
                m = x;
            }
        }
        m
    }

    pub mod inner {
        #[inline(never)]
        pub fn fold_with<F: Fn(u64, u64) -> u64>(xs: &[u64], f: F) -> u64 {
            xs.iter().fold(0, |a, &b| f(a, b))
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    use shapes::Shape;
    let r = shapes::Rect::new(source() + 2, 3);
    let s = shapes::Square(source() + 4);
    let items: [&dyn shapes::Shape; 2] = [&r, &s];
    let a = shapes::total(&items) + r.name().len() as u64 + s.name().len() as u64;
    let xs = [source(), 7, 3, a];
    let b = math::largest(&xs) + math::largest(&[1u8, source() as u8, 9]) as u64;
    let c = math::inner::fold_with(&xs, |x, y| x.wrapping_mul(31) ^ y);
    sink(a + b + c);
    loop {
        sink(0);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        sink(1);
    }
}
