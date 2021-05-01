use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fs;

fn rand_xor(input: &Vec<u8>) -> String {
    let mut rng = StdRng::seed_from_u64(13371337);
    return input
        .into_iter()
        .map(|c| (c ^ rng.gen::<u8>()) as char)
        .collect();
}

fn main() {
    let data = fs::read_to_string("out.txt").expect("File not found");
    let data = hex::decode(data).expect("Decode error");
    let flag = rand_xor(&data);
    println!("{}", flag);
}
