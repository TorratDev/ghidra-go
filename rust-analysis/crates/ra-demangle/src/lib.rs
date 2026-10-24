//! Demanglers with Ghidra's naming rules.
//!
//! Each scheme produces what Ghidra's demangler of the same name produces:
//! a leaf `name` and a `namespace` path, the parts Ghidra applies as the
//! symbol name and its parent namespaces.
//!
//! | Ghidra                        | here                                   |
//! |-------------------------------|----------------------------------------|
//! | `GnuDemangler` + `GnuDemanglerParser` | [`gnu`]: `cpp_demangle` text (libiberty-compatible, as Ghidra's bundled binutils demangler) + parser port |
//! | `RustDemangler` (legacy, v0)  | [`rust`]: legacy decoder port, v0 via `rustc-demangle` |
//! | `MicrosoftDemangler` (MDMang) | [`msvc`]: `msvc-demangler`             |
//!
//! Behaviour follows Ghidra 12.1.4, the oracle the differential tests use.

pub mod gnu;
pub mod msvc;
pub mod rust;
mod util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Gnu,
    Rust,
    Msvc,
}

impl Scheme {
    /// The Ghidra demangler class this scheme mirrors.
    pub fn ghidra_class(self) -> &'static str {
        match self {
            Scheme::Gnu => "GnuDemangler",
            Scheme::Rust => "RustDemangler",
            Scheme::Msvc => "MicrosoftDemangler",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demangled {
    pub scheme: Scheme,
    /// Parent namespaces, outermost first.
    pub namespace: Vec<String>,
    /// Leaf name as Ghidra applies it (`area`, `~Rect`, `operator.new`).
    pub name: String,
    pub is_function: bool,
    /// The full demangled text the name was derived from.
    pub full: String,
}

impl Demangled {
    /// `a::b`, or `None` for the global namespace.
    pub fn namespace_string(&self) -> Option<String> {
        (!self.namespace.is_empty()).then(|| self.namespace.join("::"))
    }
}

/// Demangles with the scheme Ghidra would pick for a program: MSVC for
/// `?` names, Rust when `rust_program` is set (Ghidra's
/// `RustDemanglerAnalyzer` only runs on programs detected as Rust),
/// otherwise GNU.
pub fn demangle(mangled: &str, rust_program: bool) -> Option<Demangled> {
    if mangled.starts_with('?') {
        return msvc::demangle(mangled);
    }
    if rust_program {
        if let Some(d) = rust::demangle(mangled) {
            return Some(d);
        }
    }
    gnu::demangle(mangled)
}

/// What kind of program a symbol comes from; selects the demangler
/// analyzers Ghidra runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramKind {
    /// PE (Windows compiler spec): `MicrosoftDemanglerAnalyzer`; the GNU
    /// analyzer does not run on Windows compiler specs.
    pub windows: bool,
    /// Tagged as Rust by the loader: `RustDemanglerAnalyzer` runs first.
    pub rust: bool,
}

/// The demangled form Ghidra's demangler analyzers apply to a symbol.
pub fn demangle_symbol(name: &str, kind: ProgramKind) -> Option<Demangled> {
    if kind.windows {
        return msvc::demangle(name);
    }
    if kind.rust {
        if let Some(d) = rust::demangle(name) {
            return Some(d);
        }
    }
    gnu::demangle_opts(name, false)
}

/// Runs one specific scheme (like calling one Ghidra demangler class).
pub fn demangle_with(scheme: Scheme, mangled: &str) -> Option<Demangled> {
    match scheme {
        Scheme::Gnu => gnu::demangle(mangled),
        Scheme::Rust => rust::demangle(mangled),
        Scheme::Msvc => msvc::demangle(mangled),
    }
}
