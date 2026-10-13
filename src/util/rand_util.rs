use the_fourth_utils::rand;


pub fn generate_random_u8_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::fill(out.as_mut_slice());
    out
}