fn main() {
    // Rebuild when UI dist changes.
    println!("cargo:rerun-if-changed=../../ui/dist");
}