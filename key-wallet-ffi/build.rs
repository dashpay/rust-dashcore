fn main() {
    println!("cargo:rerun-if-changed=src/key_wallet.udl");
    uniffi::generate_scaffolding("src/key_wallet.udl").unwrap();
}
