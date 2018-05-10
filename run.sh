sudo docker run -v $PWD/rust-sgx-sdk:/root/sgx -v $PWD/core:/root/sgx/samplecode/BCSM_SGX -ti --device /dev/isgx baiduxlab/sgx-rust
