extern crate getopts;
extern crate openssl;
extern crate rpassword;

fn read_contents(path: &str) -> std::io::Result<Vec<u8>> {
    use std::error::Error;
    use std::fs::File;
    use std::io::BufReader;
    use std::io::prelude::*;

    let file = match File::open(path) {
        Err(why) => panic!("Couldn't open {}: {}", path, why.description()),
        Ok(file) => file,
    };

    let mut buf_reader = BufReader::new(file);
    let mut contents: Vec<u8> = Vec::new();
    buf_reader.read_to_end(&mut contents)?;

    Ok(contents)
}

fn verify_data(key_data: &[u8], password: &[u8], data: &[u8], signature: &[u8]) -> bool {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;

    let private_key = match PKey::private_key_from_pem_passphrase(key_data, password) {
        Err(_) => panic!("Couldn't load private key from PEM file"),
        Ok(private_key) => private_key,
    };

    let mut verifier = match Verifier::new(MessageDigest::sha256(), &private_key) {
        Err(_) => panic!("Couldn't create a sha256 Verifier from private_key"),
        Ok(verifier) => verifier,
    };

    match verifier.update(data) {
        Err(_) => panic!("Couldn't update verifier with data"),
        Ok(()) => (),
    };

    let result = match verifier.finish(signature) {
        Err(_) => panic!("Couldn't finish verifying signature"),
        Ok(result) => result,
    };

    return result;
}

fn main() {
    use std::env;
    use getopts::Options;

    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.reqopt("k", "", "Path to private key", "KEY");
    opts.reqopt("d", "", "Path to the data", "DATA");
    opts.reqopt("s", "", "Path to the signature", "SIGNATURE");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    let private_key_path = matches.opt_str("k").expect("Missing path to private key");
    let data_path = matches.opt_str("d").expect("Missing path to private key");
    let signature_path = matches.opt_str("s").expect("Missing path to signature");

    let pem_data = read_contents(&private_key_path).expect("Unable to ready private key");
    let password = rpassword::prompt_password_stdout("Enter pass phrase for private key:").expect("Unable to get input");

    let signature = read_contents(&signature_path).expect("Unable to read signature");
    let data = read_contents(&data_path).expect("Unable to read data");

    println!("Signature match: {}",
             verify_data(pem_data.as_slice(), password.as_bytes(), data.as_slice(), signature.as_slice()));
}
