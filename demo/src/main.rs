/*
 * Copyright © 2020-2022 Mrack
 * Email: Mrack@qq.com
 */

#[inline(never)]
fn verify(input: &String) -> bool {
    let key = vec!['m', 'r', 'a', 'c', 'k'];
    let input_arr = input.as_bytes();
    if key.len() != input_arr.len() {
        return false;
    }
    for (i, c) in input_arr.iter().enumerate() {
        if key[i] as u8 != *c {
            return false;
        }
    }
    true
}


fn main() {
    loop {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
            
        input = input.trim().to_string();

        if verify(&input.to_ascii_lowercase()) {
            println!("Thank you for your purchase! key is {}", input);
            break;
        } else {
            println!("This unauthorized key.")
        }
    }
}
