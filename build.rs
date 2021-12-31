extern crate cc;


fn main() {
    cc::Build::new().file("ext/blake/blake_ref.c").compile("libblake.a");
}
