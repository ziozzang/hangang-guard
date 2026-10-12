fn main() {
    println!(
        "cargo:rustc-env=GUARD_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
