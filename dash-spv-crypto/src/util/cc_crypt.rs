use std::os::raw::c_void;
use crate::keys::KeyError;

// const K_CCENCRYPT: u32 = 0;
// const K_CCDECRYPT: u32 = 1;

pub enum Operation {
    Encrypt = 0,
    Decrypt = 1,
}


extern "C" {
    fn CCCrypt(
        operation: u32,
        alg: u32,
        options: u32,
        key: *const c_void,
        key_length: usize,
        iv: *const c_void,
        data_in: *const c_void,
        data_in_length: usize,
        data_out: *mut c_void,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;
}

#[allow(unused)]
fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    use secp256k1::rand;
    use secp256k1::rand::distributions::Uniform;
    use secp256k1::rand::Rng;
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, 255);
    (0..size).map(|_| rng.sample(&range)).collect()
}

pub fn aes256_encrypt_decrypt(operation: Operation, data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Vec<u8>, KeyError> {
    let operation = match operation {
        Operation::Encrypt => 0, // kCCEncrypt
        Operation::Decrypt => 1, // kCCDecrypt
    };
    let alg = 0; // kCCAlgorithmAES
    let options = 0x0001; // kCCOptionPKCS7Padding
    let data_ref = data.as_ref();
    let key_ref = key.as_ref();
    let iv_ref = iv.as_ref();
    let data_in_len = data_ref.len();
    let data_out_len = data_in_len + 16; // Add space for kCCBlockSizeAES128
    let mut data_out = vec![0u8; data_out_len];
    let mut bytes_written: usize = 0;
    let result = unsafe {
        CCCrypt(
            operation as u32,
            alg,
            options,
            key_ref.as_ptr() as *const c_void,
            key_ref.len(),
            iv_ref.as_ptr() as *const c_void,
            data_ref.as_ptr() as *const c_void,
            data_in_len,
            data_out.as_mut_ptr() as *mut c_void,
            data_out_len,
            &mut bytes_written as *mut usize,
        )
    };

    if result == 0 {
        // kCCSuccess
        data_out.truncate(bytes_written);
        Ok(data_out)
    } else {
        Err(KeyError::CCCrypt(result))
    }
}
