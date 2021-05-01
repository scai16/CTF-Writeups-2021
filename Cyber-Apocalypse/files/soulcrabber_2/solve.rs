use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fs;
use std::time::UNIX_EPOCH;

fn get_mtime(filename: &str) -> u64 {
    let metadata = fs::metadata(filename).expect("File not found");
    return metadata.modified().unwrap()
        .duration_since(UNIX_EPOCH).unwrap()
        .as_secs();
}

fn rand_xor(input: &Vec<u8>, seed: u64) -> String {
    let mut rng = StdRng::seed_from_u64(seed);
    return input
        .into_iter()
        .map(|c| (c ^ rng.gen::<u8>()) as char)
        .collect();
}

fn find_flag(input: Vec<u8>, init_seed: u64) -> String {
    let mut seed = init_seed;
    loop {
        let flag = rand_xor(&input, seed);
        if flag.contains("CHTB{") {
            // println!("{}", seed);
            return flag;
        }
        seed -= 1;
    }
}

fn main() -> std::io::Result<()> {
    let data = fs::read_to_string("out.txt").expect("File not found");
    let data = data.strip_suffix("\n").unwrap_or(&data);
    let data = hex::decode(data).expect("Decode error");
    let mtime = get_mtime("out.txt");
    let flag = find_flag(data, mtime);
    println!("{}", flag);
    Ok(())
}
