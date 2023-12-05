extern crate embed_resource;
fn main() {
    // decrease binary entropy
    embed_resource::compile("star_wars.rc", embed_resource::NONE);
}