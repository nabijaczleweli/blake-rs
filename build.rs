extern crate gcc;


fn main() {
    gcc::Config::new()
        .file("ext/blake/blake_ref.c")
        .compile("libblake.a");
}
