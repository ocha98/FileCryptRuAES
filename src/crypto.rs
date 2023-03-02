use std::ffi::OsString;
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher,  SaltString
    },
    Argon2
};

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockEncryptMut, BlockDecryptMut,  KeyIvInit};
use cbc::{Encryptor, Decryptor};

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

use sha2::Sha512;
use hmac::{Hmac, Mac};

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PlainData {
    pub data: Vec<u8>,
    pub file_name: OsString,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncFileBody  {
    data:  Vec<u8>,
    b64_salt: Vec<u8>,
    iv:  Vec<u8>,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncFile {
    body: EncFileBody,
    hmac: Vec<u8>,
}

pub fn encrypt<T: AsRef<Path>>(plain_file: T, raw_password: &String) -> EncFile {
    // 入力されたパスワードをハッシュ化し、ハッシュ値をAESとHMacのKeyとする
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hashed = argon2.hash_password(raw_password.as_bytes(), &salt).unwrap().hash.unwrap();
    let key = password_hashed.as_bytes();
    
    // 暗号化するファイルを開く
    let f = File::open(&plain_file).unwrap();
    let mut bfr = BufReader::new(f);
    let mut file_data = Vec::new();
    bfr.read_to_end(&mut file_data).unwrap();
    let file_name = plain_file.as_ref().file_name().unwrap();
    let prain_data = PlainData {
        data: file_data,
        file_name: file_name.to_os_string(),
    };

    // 暗号化するデータをバイト列に変換
    let plain_data = bincode::serialize(&prain_data).unwrap();

    // AESのencryptorを準備
    let mut rang = StdRng::from_entropy(); 
    let mut iv = [0u8; 16];
    rang.fill_bytes(&mut iv);
    let encryptor = Encryptor::<Aes256>::new(key.into(), &iv.into());

    // 暗号化する
    let mut buffer = vec![0u8; plain_data.len() + 128];// 少し多めに取る
    let enc_data = encryptor.encrypt_padded_b2b_mut::<Pkcs7>(&plain_data, &mut buffer).unwrap();

    // EncFileのBodyを作成
    let mut b64_salt = [0u8; 16];
    let b64_salt = salt.b64_decode(&mut b64_salt).unwrap();
    let enc_file_body = EncFileBody {
        data: enc_data.to_vec(),
        b64_salt: b64_salt.to_vec(),
        iv: iv.to_vec(),
    };
    let raw_enc_file_body = bincode::serialize(&enc_file_body).unwrap();

    // bodyのHMacを取得
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    mac.update(&raw_enc_file_body);
    let hmac = mac.finalize().into_bytes();

    // EncFileを作成
    let enc_file = EncFile {
        body: enc_file_body,
        hmac: hmac.to_vec(),
    };

    enc_file
}

pub fn decrypt<T: AsRef<Path>>(crypt_file: T, raw_password: &String) -> PlainData {
    // 暗号化されたファイルを開く
    let f = File::open(crypt_file).unwrap();
    let mut bfr = BufReader::new(f);
    let mut file_data = Vec::new();
    bfr.read_to_end(&mut file_data).unwrap();


    let enc_file: EncFile = bincode::deserialize(&file_data).expect("ファイルが壊れています");
    let enc_file_body = &enc_file.body;

    // パスワードをハッシュ化 
    let salt = SaltString::b64_encode(&enc_file_body.b64_salt).unwrap();
    let argon2 = Argon2::default();
    let password_hashed = argon2.hash_password(raw_password.as_bytes(), &salt).unwrap().hash.unwrap();
    let key = password_hashed.as_bytes();

    // hmacを検証
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    let raw_enc_file_body = bincode::serialize(&enc_file_body).unwrap();
    mac.update(&raw_enc_file_body);
    mac.verify_slice(&enc_file.hmac).expect("パスワードが異なるか、ファイルが壊れています");

    // AESのdecryptorを用意
    let decryptor = Decryptor::<Aes256>::new(key.into(), enc_file_body.iv[..].into());

    // 復号化する
    let mut buffer = vec![0u8; file_data.len() + 128]; // 少し多めにする
    let raw_plain_data = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(&enc_file_body.data, &mut buffer).unwrap();

    // 復号化したデータを取り出す
    let plain_data:PlainData = bincode::deserialize(&raw_plain_data).unwrap();

    plain_data
}



#[cfg(test)]
mod test {
    use std::{path, fs::File, io::{BufReader, Read}};

    use crate::{crypto::{encrypt, decrypt}, uitl::file_writer};
    #[test]
    fn test_encryption_decryption_file_match() {
        let file_dir = "test_files";
        let target = path::PathBuf::from(file_dir);
        let files = target.read_dir().unwrap();
        for dir_entry in files {
            let file_path = dir_entry.unwrap().path();
            let save_path = "tmp/a.enc";
            let password = "abc123@".to_string();


            let enc_data = encrypt(&file_path, &password);

            file_writer(enc_data, save_path);

            let dec_data = decrypt(save_path, &password);

            let f = File::open(&file_path).unwrap();
            let mut bfr = BufReader::new(f);
            let mut raw_plain_data = Vec::new();
            bfr.read_to_end(&mut raw_plain_data).unwrap();
            assert_eq!(dec_data.data, raw_plain_data);


        }
    }

    #[test]
    #[should_panic(expected = "パスワードが異なるか、ファイルが壊れています")]
    fn test_panic_on_password_mismatch(){
        let file_path = "test_files/random_binary";

        let save_path = "tmp/a.enc";
        let password = "abc123@".to_string();


        let enc_data = encrypt(&file_path, &password);

        file_writer(enc_data, save_path);
        
        let diff_pass = "ssss".to_string();
        let _dec_data = decrypt(save_path, &diff_pass);


    }

}