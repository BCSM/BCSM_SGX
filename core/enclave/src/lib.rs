// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "bcsmsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_tseal;

//extern crate sgx_rand_derive;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_tdh;


use sgx_types::*;
use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tcrypto::*;
use std::vec::Vec;
use std::slice;
use std::ptr;
use sgx_rand::{Rng, StdRng};
use sgx_tseal::{SgxSealedData};

#[derive(Copy, Clone, Default, Debug)]
struct RandData {
    key: u32,
    rand: [u8; 16],
}

unsafe impl ContiguousMemory for RandData {}

#[no_mangle]
pub extern "C" fn ecc_keygen(pk_gx: &mut [u8; SGX_ECP256_KEY_SIZE],
                             pk_gy: &mut [u8; SGX_ECP256_KEY_SIZE],
                             sk: &mut [u8; SGX_ECP256_KEY_SIZE]) -> sgx_status_t {
    println!("ecc_keygen invoked!");
    let ecc_state = SgxEccHandle::new();
    let res = ecc_state.open();
    match res {
        Err(x) => {
            return x;
        }
        Ok(()) => {
        }
    }

    //    let (prv_key, pub_key) = try!(ecc_state.create_key_pair());
    let res = ecc_state.create_key_pair();
    //    let (prv_key, pub_key): (sgx_ec256_private_t, sgx_ec256_public_t);
    match res {
        Ok((prv_key, pub_key)) => {
            *pk_gx = pub_key.gx;
            *pk_gy = pub_key.gy;
            *sk = prv_key.r;
        }
        Err(e) => return e
    }

    // let secret_key: [u8; SGX_ECP256_KEY_SIZE] = [0xde, 0x8c, 0xab, 0xf7, 0x7b, 0x11, 0x6e, 0x06, 0x31, 0x02, 0xb6, 0xee,
    //        0x30, 0xa9, 0xfd, 0xc4, 0x37, 0xd4, 0xcf, 0x01, 0x37, 0x8b, 0x5d, 0xe1, 0xfc, 0x0a, 0x5a, 0x99, 0x54, 0xa9, 0xe3, 0x93];

    sgx_status_t::SGX_SUCCESS
}

fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

#[no_mangle]
pub extern "C" fn doctor_ecc_keygen(pk_gx: &mut [u8; SGX_ECP256_KEY_SIZE],
                             pk_gy: &mut [u8; SGX_ECP256_KEY_SIZE],
                             sealed_log: * mut u8,
                             sealed_log_size: u32) -> sgx_status_t {
                             //sk: &mut [u8; SGX_ECP256_KEY_SIZE]) -> sgx_status_t {
    println!("ecc_keygen invoked!");
    let ecc_state = SgxEccHandle::new();
    let res = ecc_state.open();
    match res {
        Err(x) => {
            return x;
        }
        Ok(()) => {
        }
    }

    println!("generate key pair!");
    //    let (prv_key, pub_key) = try!(ecc_state.create_key_pair());
    let res = ecc_state.create_key_pair();
    //    let (prv_key, pub_key): (sgx_ec256_private_t, sgx_ec256_public_t);
    match res {
        Ok((prv_key, pub_key)) => {
            *pk_gx = pub_key.gx;
            *pk_gy = pub_key.gy;
            //*sk = prv_key.r;
            println!("sealing secret key!");
            /*for x in prv_key.r.clone().iter() {
                println!("{}", x);
            }*/

            let aad: [u8; 0] = [0_u8; 0];
            let result = SgxSealedData::<[u8; SGX_ECP256_KEY_SIZE]>::seal_data(&aad, &prv_key.r);
            let sealed_data = match result {
                Ok(x) => x,
                Err(ret) => { return ret; },
            };

            let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
            if opt.is_none() {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
        Err(e) => return e
    }

    // let secret_key: [u8; SGX_ECP256_KEY_SIZE] = [0xde, 0x8c, 0xab, 0xf7, 0x7b, 0x11, 0x6e, 0x06, 0x31, 0x02, 0xb6, 0xee,
    //        0x30, 0xa9, 0xfd, 0xc4, 0x37, 0xd4, 0xcf, 0x01, 0x37, 0x8b, 0x5d, 0xe1, 0xfc, 0x0a, 0x5a, 0x99, 0x54, 0xa9, 0xe3, 0x93];

    sgx_status_t::SGX_SUCCESS
}

fn set_error(sgx_ret: sgx_status_t) -> sgx_status_t {

    let ret = match sgx_ret {
        sgx_status_t::SGX_ERROR_OUT_OF_MEMORY => sgx_status_t::SGX_ERROR_OUT_OF_MEMORY,
        _ => sgx_status_t::SGX_ERROR_UNEXPECTED,
    };
    ret
}

const EC_LABEL_LENGTH: usize = 3;
const EC_SMK_LABEL: [u8; EC_LABEL_LENGTH] = [0x53, 0x4D, 0x4B];
//const EC_AEK_LABEL: [u8; EC_LABEL_LENGTH] = [0x41, 0x45, 0x4B];
const EC_DERIVATION_BUFFER_SIZE: usize = 7;

fn derive_key(shared_key: &sgx_ec256_dh_shared_t,
              label: &[u8; EC_LABEL_LENGTH]) -> SgxResult<sgx_ec_key_128bit_t> {

    let cmac_key = sgx_cmac_128bit_key_t::default();
    let mut key_derive_key = try!(rsgx_rijndael128_cmac_msg(&cmac_key, shared_key).map_err(set_error));

    //derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080)
    let mut derivation_buffer = [0_u8; EC_DERIVATION_BUFFER_SIZE];
    derivation_buffer[0] = 0x01;
    derivation_buffer[1] = label[0];
    derivation_buffer[2] = label[1];
    derivation_buffer[3] = label[2];
    derivation_buffer[4] = 0x00;
    derivation_buffer[5] = 0x80;
    derivation_buffer[6] = 0x00;

    let result = rsgx_rijndael128_cmac_slice(&key_derive_key, &derivation_buffer).map_err(set_error);
    key_derive_key = Default::default();
    result
}

#[no_mangle]
pub extern "C" fn doctor_generate_rx(key: &[u8;16],
                                     plaintext: *const u8,
                                     text_len: usize,
                                     patient_iv: &mut [u8;12],
                                     patient_ciphertext: *mut u8,
                                     patient_mac: &mut [u8;16],
                                     pk_gx: &[u8; SGX_ECP256_KEY_SIZE],
                                     pk_gy: &[u8; SGX_ECP256_KEY_SIZE],
                                     sealed_log: * mut u8,
                                     sealed_log_size: u32,
                                     signature_x: &mut [u32; SGX_NISTP_ECP256_KEY_SIZE],
                                     signature_y: &mut [u32; SGX_NISTP_ECP256_KEY_SIZE],
                                     ecc_pk_gx: &mut [u8; SGX_ECP256_KEY_SIZE],
                                     ecc_pk_gy: &mut [u8; SGX_ECP256_KEY_SIZE],
                                     ecc_cipher: &mut [u8; SGX_AESGCM_KEY_SIZE],
                                     key_iv: &mut [u8;12],
                                     key_ciphertext: *mut u8,
                                     key_mac: &mut [u8;16]
                                     ) -> sgx_status_t {

    let ecc_state = SgxEccHandle::new();
    let res = ecc_state.open();
    match res {
        Err(x) => {
            return x;
        }
        Ok(()) => {
        }
    }


    let mut iv_array: [u8;SGX_AESGCM_IV_SIZE] = [0; SGX_AESGCM_IV_SIZE];
    println!("aes_gcm_128_encrypt using PatientID started!");
    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut iv_array);

    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, text_len) };
    let mut ciphertext_vec: Vec<u8> = vec![0; text_len];
    let aad_array: [u8; 0] = [0; 0];
    let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];
    if plaintext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let ciphertext_slice = &mut ciphertext_vec[..];
    println!("aes_gcm_128_encrypt parameter prepared! {}, {}",
              plaintext_slice.len(),
              ciphertext_slice.len());

    let result = rsgx_rijndael128GCM_encrypt(key,
                                             &plaintext_slice,
                                             &iv_array,
                                             &aad_array,
                                             ciphertext_slice,
                                             &mut mac_array);

    println!("rsgx calling returned!");
    match result {
        Err(x) => {
            println!("Error!!!!!!!!!!!!!!!");
            return x;
        }
        Ok(()) => {
            unsafe{
                ptr::copy_nonoverlapping(ciphertext_slice.as_ptr(),
                                         patient_ciphertext,
                                         text_len);
            }
            *patient_iv = iv_array;
            *patient_mac = mac_array;
        }
    }

    println!("get government public key!");
    let mut government_pk: sgx_ec256_public_t = sgx_ec256_public_t::default();
    government_pk.gx = [0xbc, 0xae, 0x99, 0x92,
                        0x32, 0x1c, 0xb9, 0x2b,
                        0x82, 0xed, 0x07, 0x31,
                        0x68, 0x0b, 0xd7, 0x2e,
                        0x3d, 0x14, 0x25, 0xe3,
                        0x35, 0xb2, 0xb8, 0x7c,
                        0x2a, 0x45, 0xe6, 0xcf,
                        0x6b, 0x8f, 0x69, 0x62];
    government_pk.gy = [0xad, 0x86, 0x19, 0xd6,
                        0x83, 0xd6, 0xa2, 0xb0,
                        0xa2, 0x75, 0xe6, 0x84,
                        0x82, 0x4b, 0x19, 0x80,
                        0x28, 0xad, 0x0b, 0x83,
                        0x92, 0x1e, 0x81, 0x62,
                        0x24, 0xf0, 0x95, 0xe9,
                        0xe2, 0x13, 0x8f, 0xc9];

    println!("generate aes key for government encryption!");
    let mut aeskey_array: [u8;SGX_AESGCM_KEY_SIZE] = [0; SGX_AESGCM_KEY_SIZE];
    let mut rand2 = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand2.fill_bytes(&mut aeskey_array);

    println!("generate ecc key pair for government encryption!");
    let res = ecc_state.create_key_pair();
    let (prv_key, pub_key): (sgx_ec256_private_t, sgx_ec256_public_t);
    match res {
        Ok((x, y)) => {
            prv_key = x;
            pub_key = y;
        }
        Err(e) => return e
    }
    *ecc_pk_gx = pub_key.gx;
    *ecc_pk_gy = pub_key.gy;

    println!("generate KDF(shared_key(prv_key, government_pk))!");
    let res = ecc_state.compute_shared_dhkey(&prv_key, &government_pk);
    let ecc_drived_key: sgx_ec_key_128bit_t;
    match res {
        Ok(x) => {
            let ret = derive_key(&x, &EC_SMK_LABEL);
            match ret {
                Ok(y) => {
                    ecc_drived_key = y;
                }
                Err(e) => return e
            }
        }
        Err(e) => return e
    }

    println!("compute derived_key xor aes key!");
    let mut ecc_cipher_array: [u8; SGX_AESGCM_KEY_SIZE] = [0; SGX_AESGCM_KEY_SIZE];
    let mut idx = 0;
    while idx < SGX_AESGCM_KEY_SIZE {
        ecc_cipher_array[idx] = ecc_drived_key[idx] ^ aeskey_array[idx];
        idx = idx + 1;
    }
    *ecc_cipher = ecc_cipher_array;
/*    for x in aeskey_array.clone().iter() {
        println!("{}", x);
    }*/

    println!("compute aes encryption for PatientID!");
    let mut ciphertext_vec2: Vec<u8> = vec![0; SGX_AESGCM_KEY_SIZE];
    let ciphertext_slice2 = &mut ciphertext_vec2[..];
    {
        let text_len = SGX_AESGCM_KEY_SIZE;
        let mut iv_array: [u8;SGX_AESGCM_IV_SIZE] = [0; SGX_AESGCM_IV_SIZE];
        println!("aes_gcm_128_encrypt for PatientID started!");
        let mut rand = match StdRng::new() {
            Ok(rng) => rng,
            Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
        };
        rand.fill_bytes(&mut iv_array);

        // Warning:!!!!
        let plaintext_slice = key.clone(); //unsafe { slice::from_raw_parts(key, text_len) };

        let aad_array: [u8; 0] = [0; 0];
        let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];
        if plaintext_slice.len() != text_len {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        println!("aes_gcm_128_encrypt parameter prepared! {}, {}",
                  plaintext_slice.len(),
                  ciphertext_slice2.len());

        let result = rsgx_rijndael128GCM_encrypt(&aeskey_array,
                                                 &plaintext_slice,
                                                 &iv_array,
                                                 &aad_array,
                                                 ciphertext_slice2,
                                                 &mut mac_array);

        println!("rsgx calling returned!");
        match result {
            Err(x) => {
                println!("Error!!!!!!!!!!!!!!!");
                return x;
            }
            Ok(()) => {
                unsafe{
                    ptr::copy_nonoverlapping(ciphertext_slice2.as_ptr(),
                                             key_ciphertext,
                                             text_len);
                }
                *key_iv = iv_array;
                *key_mac = mac_array;
            }
        }
    }

    println!("generate record!");
    let mut rx: Vec<u8> = vec![0; patient_iv.len()
                                //+ text_len
                                + ciphertext_slice.len()
                                + patient_mac.len()
                                + pub_key.gx.len()
                                + pub_key.gy.len()
                                + ecc_cipher_array.len()
                                + key_iv.len()
                                + ciphertext_slice2.len()
                                + key_mac.len()];
    let mut rx_cnt = 0;
    for x in patient_iv.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ciphertext_slice {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in patient_mac.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in pub_key.gx.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in pub_key.gy.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_cipher_array.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in key_iv.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ciphertext_slice2 {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in key_mac.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    let rx_slice = &mut rx.clone()[..];
    /*for x in rx.clone().iter() {
        println!("{}", x);
    }*/

    println!("unseal signing key!");
    let mut private: sgx_ec256_private_t = sgx_ec256_private_t::default();
    let opt = from_sealed_log::<[u8; SGX_ECP256_KEY_SIZE]>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };
    let sealed_ret = sealed_data.unseal_data();
    let unsealed_data = match sealed_ret {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let data = unsealed_data.get_decrypt_txt();
    private.r = *data;
    /*for x in data.clone().iter() {
        println!("{}", x);
    }*/

    println!("signing record!");
    let sign_ret = ecc_state.ecdsa_sign_slice::<u8>(rx_slice, &private);
    match sign_ret {
        Err(x) => {
            return x;
        }
        Ok(sig) => {
            *signature_x = sig.x;
            *signature_y = sig.y;
        }
    }

    println!("check record!");
    let mut public: sgx_ec256_public_t = sgx_ec256_public_t::default();
    public.gx = *pk_gx;
    public.gy = *pk_gy;

    let mut signature: sgx_ec256_signature_t = sgx_ec256_signature_t::default();
    signature.x = *signature_x;
    signature.y = *signature_y;

    let sign_ret = ecc_state.ecdsa_verify_slice::<u8>(rx_slice, &public, &signature);
    match sign_ret {
        Err(x) => {
            return x;
        }
        Ok(true) => {
            sgx_status_t::SGX_SUCCESS
        }
        Ok(false) => {
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
    //sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn government_decode_rx(gov_sk:&[u8; SGX_ECP256_KEY_SIZE],
                                       ciphertext: *const u8,
                                       text_len: usize,
                                       patient_iv: &[u8;12],
                                       patient_mac: &[u8;16],
                                       plaintext: *mut u8,
                                       pk_gx: &[u8; SGX_ECP256_KEY_SIZE],
                                       pk_gy: &[u8; SGX_ECP256_KEY_SIZE],
                                       signature_x: &[u32; SGX_NISTP_ECP256_KEY_SIZE],
                                       signature_y: &[u32; SGX_NISTP_ECP256_KEY_SIZE],
                                       ecc_pk_gx: &[u8; SGX_ECP256_KEY_SIZE],
                                       ecc_pk_gy: &[u8; SGX_ECP256_KEY_SIZE],
                                       ecc_cipher: &[u8; SGX_AESGCM_KEY_SIZE],
                                       key_iv: &[u8;12],
                                       key_ciphertext: *const u8,
                                       key_mac: &[u8;16]
                                       ) -> sgx_status_t {

    let ecc_state = SgxEccHandle::new();
    let res = ecc_state.open();
    match res {
       Err(x) => {
           return x;
       }
       Ok(()) => {
       }
    }

    println!("government_decode_rx invoked!");
    println!("get government private key!");
    let mut government_sk: sgx_ec256_private_t = sgx_ec256_private_t::default();
    government_sk.r = *gov_sk;

    println!("get temporary public key!");
    let mut tmp_pk: sgx_ec256_public_t = sgx_ec256_public_t::default();
    tmp_pk.gx = *ecc_pk_gx;
    tmp_pk.gy = *ecc_pk_gy;
    //tmp_pk.gx = *pk_gx;
    //tmp_pk.gy = *pk_gy;
    /*for x in tmp_pk.gx.clone().iter() {
        println!("{}", x);
    }
    for x in tmp_pk.gy.clone().iter() {
        println!("{}", x);
    }*/

    println!("generate derived key!");
    let res = ecc_state.compute_shared_dhkey(&government_sk, &tmp_pk);
    let ecc_drived_key: sgx_ec_key_128bit_t;
    match res {
        Ok(x) => {
            println!("compute_shared_dhkey succeed!");
            let ret = derive_key(&x, &EC_SMK_LABEL);
            match ret {
                Ok(y) => {
                    ecc_drived_key = y;
                }
                Err(e) => return e
            }
        }
        Err(e) => {
            println!("Error!!!!!!!!");
            return e
        }
    }

    println!("compute ecc decryption for aes temporary key!");
    let mut tmp_aeskey: [u8; SGX_AESGCM_KEY_SIZE] = [0; SGX_AESGCM_KEY_SIZE];
    let mut idx = 0;
    while idx < SGX_AESGCM_KEY_SIZE {
        tmp_aeskey[idx] = ecc_drived_key[idx] ^ ecc_cipher[idx];
        idx = idx + 1;
    }

    println!("AES decryption for patientID!");
    let mut patientid: [u8; SGX_AESGCM_KEY_SIZE] = [0; SGX_AESGCM_KEY_SIZE];
    let ciphertext_slice2 = unsafe { slice::from_raw_parts(key_ciphertext, SGX_AESGCM_KEY_SIZE) };
    {
        let text_len = SGX_AESGCM_KEY_SIZE;
        let mut plaintext_vec: Vec<u8> = vec![0; text_len];
        // Second, for data with known length, we use array with fixed length.
        let aad_array: [u8; 0] = [0; 0];

        if ciphertext_slice2.len() != text_len {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }

        let plaintext_slice = &mut plaintext_vec[..];
        println!("AES decryption for patientID! {}, {}",
                  ciphertext_slice2.len(),
                  plaintext_slice.len());

        // After everything has been set, call API
        let result = rsgx_rijndael128GCM_decrypt(&tmp_aeskey,
                                                 &ciphertext_slice2,
                                                 key_iv,
                                                 &aad_array,
                                                 key_mac,
                                                 plaintext_slice);

        println!("rsgx calling returned!");

        // Match the result and copy result back to normal world.
        match result {
            Err(x) => {
                return x;
            }
            Ok(()) => {
                //patientid = plaintext_slice;
                let mut idx = 0;
                while idx < SGX_AESGCM_KEY_SIZE {
                    patientid[idx] = plaintext_slice[idx];
                    idx = idx + 1;
                }
            }
        }
    }

    println!("decrypt patient info!");
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    let aad_array: [u8; 0] = [0; 0];

    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let plaintext_slice = &mut plaintext_vec[..];
    println!("decrypt patient info prepared! {}, {}",
              ciphertext_slice.len(),
              plaintext_slice.len());

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_decrypt(&patientid,
                                             &ciphertext_slice,
                                             patient_iv,
                                             &aad_array,
                                             patient_mac,
                                             plaintext_slice);

    println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext_slice.as_ptr(),
                                         plaintext,
                                         text_len);
            }
        }
    }

    println!("generate record!");
    let mut rx: Vec<u8> = vec![0; patient_iv.len()
                                //+ text_len
                                + ciphertext_slice.len()
                                + patient_mac.len()
                                + ecc_pk_gx.len()
                                + ecc_pk_gy.len()
                                + ecc_cipher.len()
                                + key_iv.len()
                                + ciphertext_slice2.len()
                                + key_mac.len()];
    let mut rx_cnt = 0;
    for x in patient_iv.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ciphertext_slice.clone() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in patient_mac.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_pk_gx.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_pk_gy.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_cipher.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in key_iv.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ciphertext_slice2 {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in key_mac.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    let rx_slice = &mut rx.clone()[..];

    println!("get public key for signature verification!");
    let mut public: sgx_ec256_public_t = sgx_ec256_public_t::default();
    public.gx = *pk_gx;
    public.gy = *pk_gy;

    println!("get signature!");
    let mut signature: sgx_ec256_signature_t = sgx_ec256_signature_t::default();
    signature.x = *signature_x;
    signature.y = *signature_y;
    /*for x in public.gy.clone().iter() {
        println!("{}", *x);
    }*/

    println!("verify signature!");
    let ecc_state = SgxEccHandle::new();
    let res = ecc_state.open();
    match res {
        Err(x) => {
            return x;
        }
        Ok(()) => {
        }
    }
    let sign_ret = ecc_state.ecdsa_verify_slice::<u8>(rx_slice, &public, &signature);
    match sign_ret {
        Err(x) => {
            return x;
        }
        Ok(true) => {
            sgx_status_t::SGX_SUCCESS
        }
        Ok(false) => {
            sgx_status_t::SGX_ERROR_INVALID_SIGNATURE
        }
    }
}

#[no_mangle]
pub extern "C" fn pharmacy_decode_rx(key: &[u8;16],
                                     ciphertext: *const u8,
                                     text_len: usize,
                                     patient_iv: &[u8;12],
                                     patient_mac: &[u8;16],
                                     plaintext: *mut u8,
                                     pk_gx: &[u8; SGX_ECP256_KEY_SIZE],
                                     pk_gy: &[u8; SGX_ECP256_KEY_SIZE],
                                     signature_x: &[u32; SGX_NISTP_ECP256_KEY_SIZE],
                                     signature_y: &[u32; SGX_NISTP_ECP256_KEY_SIZE],
                                     ecc_pk_gx: &[u8; SGX_ECP256_KEY_SIZE],
                                     ecc_pk_gy: &[u8; SGX_ECP256_KEY_SIZE],
                                     ecc_cipher: &[u8; SGX_AESGCM_KEY_SIZE],
                                     key_iv: &[u8;12],
                                     key_ciphertext: *const u8,
                                     key_mac: &[u8;16]
                                     ) -> sgx_status_t {
    println!("pharmacy_decode_rx invoked!");

    // First, for data with unknown length, we use vector as builder.
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    let aad_array: [u8; 0] = [0; 0];

    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let plaintext_slice = &mut plaintext_vec[..];
    println!("pharmacy_decode_rx prepared! {}, {}",
              ciphertext_slice.len(),
              plaintext_slice.len());

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_decrypt(key,
                                             &ciphertext_slice,
                                             patient_iv,
                                             &aad_array,
                                             patient_mac,
                                             plaintext_slice);

    println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext_slice.as_ptr(),
                                         plaintext,
                                         text_len);
            }
        }
    }

    let ciphertext_slice2 = unsafe { slice::from_raw_parts(key_ciphertext, SGX_AESGCM_KEY_SIZE) };

    println!("generate record!");
    let mut rx: Vec<u8> = vec![0; patient_iv.len()
                                //+ text_len
                                + ciphertext_slice.len()
                                + patient_mac.len()
                                + ecc_pk_gx.len()
                                + ecc_pk_gy.len()
                                + ecc_cipher.len()
                                + key_iv.len()
                                + ciphertext_slice2.len()
                                + key_mac.len()];
    let mut rx_cnt = 0;
    for x in patient_iv.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ciphertext_slice.clone() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in patient_mac.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_pk_gx.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_pk_gy.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ecc_cipher.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in key_iv.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in ciphertext_slice2 {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    for x in key_mac.clone().iter() {
        rx[rx_cnt] = *x;
        rx_cnt = rx_cnt + 1;
    }
    let rx_slice = &mut rx.clone()[..];

    println!("get public key for signature verification!");
    let mut public: sgx_ec256_public_t = sgx_ec256_public_t::default();
    public.gx = *pk_gx;
    public.gy = *pk_gy;

    println!("get signature!");
    let mut signature: sgx_ec256_signature_t = sgx_ec256_signature_t::default();
    signature.x = *signature_x;
    signature.y = *signature_y;
    /*for x in public.gy.clone().iter() {
        println!("{}", *x);
    }*/

    println!("verify signature!");
    let ecc_state = SgxEccHandle::new();
    let res = ecc_state.open();
    match res {
        Err(x) => {
            return x;
        }
        Ok(()) => {
        }
    }
    let sign_ret = ecc_state.ecdsa_verify_slice::<u8>(rx_slice, &public, &signature);
    match sign_ret {
        Err(x) => {
            return x;
        }
        Ok(true) => {
            sgx_status_t::SGX_SUCCESS
        }
        Ok(false) => {
            sgx_status_t::SGX_ERROR_INVALID_SIGNATURE
        }
    }
}

/// An AES-GCM-128 encrypt function sample.
///
/// # Parameters
///
/// **key**
///
/// Key used in AES encryption, typed as &[u8;16].
///
/// **plaintext**
///
/// Plain text to be encrypted.
///
/// **text_len**
///
/// Length of plain text, unsigned int.
///
/// **iv**
///
/// Initialization vector of AES encryption, typed as &[u8;12].
///
/// **ciphertext**
///
/// A pointer to destination ciphertext buffer.
///
/// **mac**
///
/// A pointer to destination mac buffer, typed as &mut [u8;16].
///
/// # Return value
///
/// **SGX_SUCCESS** on success
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** Indicates the parameter is invalid.
///
/// **SGX_ERROR_UNEXPECTED** Indicates that encryption failed.
///
/// # Requirements
///
/// The caller should allocate the ciphertext buffer. This buffer should be
/// at least same length as plaintext buffer. The caller should allocate the
/// mac buffer, at least 16 bytes.

#[no_mangle]
pub extern "C" fn aes_gcm_128_encrypt(key: &[u8;16],
                                      plaintext: *const u8,
                                      text_len: usize,
                                      iv: &[u8;12],
                                      ciphertext: *mut u8,
                                      mac: &mut [u8;16]) -> sgx_status_t {
    println!("aes_gcm_128_encrypt invoked!");

    // First, we need slices for input
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, text_len) };

    // Here we need to initiate the ciphertext buffer, though nothing in it.
    // Thus show the length of ciphertext buffer is equal to plaintext buffer.
    // If not, the length of ciphertext_vec will be 0, which leads to argument
    // illegal.
    let mut ciphertext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    // Here we cannot use slice::from_raw_parts because it provides &[u8]
    // instead of &[u8,16].
    let aad_array: [u8; 0] = [0; 0];
    let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];

    // Always check the length after slice::from_raw_parts
    if plaintext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let ciphertext_slice = &mut ciphertext_vec[..];
    println!("aes_gcm_128_encrypt parameter prepared! {}, {}",
              plaintext_slice.len(),
              ciphertext_slice.len());

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_encrypt(key,
                                             &plaintext_slice,
                                             iv,
                                             &aad_array,
                                             ciphertext_slice,
                                             &mut mac_array);
    println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe{
                ptr::copy_nonoverlapping(ciphertext_slice.as_ptr(),
                                         ciphertext,
                                         text_len);
            }
            *mac = mac_array;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// An AES-GCM-128 decrypt function sample.
///
/// # Parameters
///
/// **key**
///
/// Key used in AES encryption, typed as &[u8;16].
///
/// **ciphertext**
///
/// Cipher text to be encrypted.
///
/// **text_len**
///
/// Length of cipher text.
///
/// **iv**
///
/// Initialization vector of AES encryption, typed as &[u8;12].
///
/// **mac**
///
/// A pointer to source mac buffer, typed as &[u8;16].
///
/// **plaintext**
///
/// A pointer to destination plaintext buffer.
///
/// # Return value
///
/// **SGX_SUCCESS** on success
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** Indicates the parameter is invalid.
///
/// **SGX_ERROR_UNEXPECTED** means that decryption failed.
///
/// # Requirements
//
/// The caller should allocate the plaintext buffer. This buffer should be
/// at least same length as ciphertext buffer.
#[no_mangle]
pub extern "C" fn aes_gcm_128_decrypt(key: &[u8;16],
                                      ciphertext: *const u8,
                                      text_len: usize,
                                      iv: &[u8;12],
                                      mac: &[u8;16],
                                      plaintext: *mut u8) -> sgx_status_t {

    println!("aes_gcm_128_decrypt invoked!");

    // First, for data with unknown length, we use vector as builder.
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    let aad_array: [u8; 0] = [0; 0];

    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let plaintext_slice = &mut plaintext_vec[..];
    println!("aes_gcm_128_decrypt parameter prepared! {}, {}",
              ciphertext_slice.len(),
              plaintext_slice.len());

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_decrypt(key,
                                             &ciphertext_slice,
                                             iv,
                                             &aad_array,
                                             mac,
                                             plaintext_slice);

    println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext_slice.as_ptr(),
                                         plaintext,
                                         text_len);
            }
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// A sample aes-cmac function.
///
/// # Parameters
///
/// **text**
///
/// The text message to be calculated.
///
/// **text_len**
///
/// An unsigned int indicate the length of input text message.
///
/// **key**
///
/// The key used in AES-CMAC, 16 bytes sized.
///
/// **cmac**
///
/// The output buffer, at least 16 bytes available.
///
/// # Return value
///
/// **SGX_SUCCESS** on success.
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** indicates invalid input parameters
///
/// # Requirement
///
/// The caller should allocate the output cmac buffer.
#[no_mangle]
pub extern "C" fn aes_cmac(text: *const u8,
                           text_len: usize,
                           key: &[u8;16],
                           cmac: &mut [u8;16]) -> sgx_status_t {

    let text_slice = unsafe { slice::from_raw_parts(text, text_len) };

    if text_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let result = rsgx_rijndael128_cmac_slice(key, &text_slice);

    match result {
        Err(x) => return x,
        Ok(m) => *cmac = m
    }

    sgx_status_t::SGX_SUCCESS
}
