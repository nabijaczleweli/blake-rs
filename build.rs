extern crate gcc;


fn main() {
    gcc::Build::new()
        .file("ext/blake/blake_ref.c")
        .compile("libblake.a");
}
