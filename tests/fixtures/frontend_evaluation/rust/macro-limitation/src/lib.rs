#[cfg(feature = "generated")]
fn generated() {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}
