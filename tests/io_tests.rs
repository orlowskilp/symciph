use std::fs::File;

use symciph::io::{read_chunks, read_key, write_chunks, write_key};

macro_rules! integration_test_data_prefix {
    () => {
        "tests/data/"
    };
}

const NUM_BLOCK_BYTES: usize = 8;

#[test]
fn read_chunks_buffer_size_8_chunks_input_60_bytes() {
    let mut file = File::open(concat!(integration_test_data_prefix!(), "in.60_bytes.txt")).unwrap();
    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 8];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 8);
    assert_eq!(last_chunk_len, 4);
}

#[test]
fn read_chunks_buffer_size_4_chunks_input_60_bytes() {
    let mut file = File::open(concat!(integration_test_data_prefix!(), "in.60_bytes.txt")).unwrap();
    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 4];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 4);
    assert_eq!(last_chunk_len, 8);

    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 4];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 4);
    assert_eq!(last_chunk_len, 4);
}

#[test]
fn read_chunks_buffer_size_2_chunks_input_8_bytes() {
    let mut file = File::open(concat!(integration_test_data_prefix!(), "in.8_bytes.txt")).unwrap();
    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 2];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 1);
    assert_eq!(last_chunk_len, 8);
}

#[test]
fn read_chunks_buffer_size_2_chunks_input_16_bytes() {
    let mut file = File::open(concat!(integration_test_data_prefix!(), "in.16_bytes.txt")).unwrap();
    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 2];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 2);
    assert_eq!(last_chunk_len, 8);
}

#[test]
fn read_chunks_buffer_size_4_chunks_input_16_bytes() {
    let mut file = File::open(concat!(integration_test_data_prefix!(), "in.16_bytes.txt")).unwrap();
    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 4];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 2);
    assert_eq!(last_chunk_len, 8);
}

#[test]
fn read_chunks_buffer_size_4_chunks_input_empty() {
    let mut file = File::open(concat!(integration_test_data_prefix!(), "in.empty.txt")).unwrap();
    let buffer = &mut [[0; NUM_BLOCK_BYTES]; 4];

    let (chunks_num, last_chunk_len) = read_chunks(&mut file, buffer).unwrap();

    assert_eq!(chunks_num, 0);
    assert_eq!(last_chunk_len, 0);
}

#[test]
fn write_two_chunks() {
    // NOTE: Check sha1sum -> expected: 5eb4a0004ea3dfc4bf2c4e779dc26904ea08da6c
    let mut file = File::create(concat!(integration_test_data_prefix!(), "out.txt")).unwrap();
    let buffer = &[[62; NUM_BLOCK_BYTES], [65; NUM_BLOCK_BYTES]];

    write_chunks(&mut file, buffer).unwrap();
}

#[should_panic]
#[test]
fn read_invalid_6_byte_key() {
    let key_path = String::from(concat!(integration_test_data_prefix!(), "6_bytes.key"));

    read_key(&key_path).unwrap();
}

#[should_panic]
#[test]
fn read_invalid_12_byte_key() {
    let key_path = String::from(concat!(integration_test_data_prefix!(), "12_bytes.key"));

    read_key(&key_path).unwrap();
}

#[test]
fn read_des_key() {
    let key_path = String::from(concat!(integration_test_data_prefix!(), "des.key"));

    let key = read_key(&key_path).unwrap();

    assert_eq!(key.len(), 1);
}

#[test]
fn read_3des_key() {
    let key_path = String::from(concat!(integration_test_data_prefix!(), "3des.key"));

    let key = read_key(&key_path).unwrap();

    assert_eq!(key.len(), 3);
}

#[test]
fn read_aes128_key() {
    let key_path = String::from(concat!(integration_test_data_prefix!(), "aes128.key"));

    let key = read_key(&key_path).unwrap();

    assert_eq!(key.len(), 2);
}

#[test]
fn read_aes256_key() {
    let key_path = String::from(concat!(integration_test_data_prefix!(), "aes256.key"));

    let key = read_key(&key_path).unwrap();

    assert_eq!(key.len(), 4);
}

#[test]
fn write_64_bit_key() {
    // NOTE: Check sha1sum -> expected: c08598945e566e4e53cf3654c922fa98003bf2f9
    let key_path = String::from(concat!(integration_test_data_prefix!(), "des.out.key"));
    let key_buffer = &[[65; NUM_BLOCK_BYTES]];

    write_key(&key_path, key_buffer).unwrap();
}
