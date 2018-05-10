# An Intel SGX Encryption and Signing Oracle

This repository is for an [Intel SGX](https://software.intel.com/en-us/sgx) signing oracle with the application to blockchain-based controlled substances monitoring.

This is part of the implementation for a course project to [CS294-144](https://berkeley-blockchain.github.io/cs294-144-s18/), Blockchain, Cryptoeconomics, and the Future of Technology, Business and Law. 

The implementation is based on [Baidu's Rust SGX SDK](https://github.com/baidu/rust-sgx-sdk).

**Author:** Yuncong Hu, UC Berkeley. 

**Acknowledgment:** Weikeng Chen, UC Berkeley.

## Motivation
We consider a world with digital prescription (Rx). There are mainly three parties as follows:
- **Doctor:** 
  - *Encryption:* A doctor uses the patient's ID (such as the combinition of patient's name, birthday and SSN) to encrypt the Rx
  - *Signing:* A doctor has a pair of signing key *SK* and *VK*. The doctor commits the *VK*	to a key transparency system, like [CONIKS](https://github.com/coniks-sys/coniks-go). The doctor uses *SK* to sign a Rx. When a Rx is signed by a doctor with valid license (namely, *VK* is active in CONIKS), the Rx becomes valid. 
- *Patient:* A patient goes to a doctor for a digital Rx. The patient then brings the digital Rx to the pharmacy to pick up the medicine. In our course project, we focus on controlled substances.
- *Pharmacy:* A pharmacy sells prescripted medicine under a doctor's Rx. The pharmacy gets the doctor's *VK* from CONIKS and checks whether the signature is valid (although on-chain Rx should already have a valid doctor signature). If the signature is valid, the pharmacy gives the medicine.
- *Government:* A government 

Now, we consider an adversary:
- *Adversary:* An adversary wants to order controlled substances from government approved pharmacies (with the market price) and sells in the underground market. In order to get controlled substances from the pharmacies, the adversary needs to obtain many valid Rx. To do that without explicitly colluding with a doctor, the adversary needs to get a doctor signing key.

We want to design a signing oracle resilient to key stealing attacks. It has two properties:
- The doctor can use this oracle to sign a piece of message that is generated honestly, possibly with two-factor authentication like a [FIDO U2F](https://www.yubico.com/solutions/fido-u2f/).
- There is no easy way to extract the signing key.

## The idea, at a high level

To build a signing oracle resilient to key stealing attacks, we need to defend against computer viruses that may compromise the whole software stack, and better other physical attacks.

We use Intel SGX (Software Guard Extensions), a platform to build secure applications that only trust Intel. We make use of the following three properties of Intel SGX:
- *Sealing:* For the same application, Intel SGX provides a unique key that remain the same even if the machine reboots. We can use this key with authenticated encryption to seal a secret that only this application (on this machine) can read.
- *Isolation:* The application runs in an isolation environment that even the operating system cannot access the memory of the protected application.
- *Remote attestation:* A remote party can attest whether the correct code is running in the Intel SGX and establish a secure communication channel.

In this application, the doctor will generate the signing key *SK* and the verifying key *VK*. The verifying key will leave the enclave, but the signing key is sealed and never leave the enclave. Later, the doctor can use the enclave program to sign an encrypted Rx, which needs to be from a honest encryption. 

## Limitations

We do not consider the doctor computing is fully stolen, as the doctor will discover and call the police. We also do not consider some pieces of hardware of the doctor's computer are replaced by the attacker, as the doctor will fail to sign new Rx and can discover.

This implementation focuses on the cryptographic functions rather than the remote attestation, the latter of which is not implemented because the application for a IAS-approved certificate is pending. 


## Installation
Readers should build the execution environment following the instructions of [rust-sgx-sdk](https://github.com/baidu/rust-sgx-sdk).

Then, the readers clone this repository:
```
git clone https://github.com/huyuncong/BCSM_SGX.git
cd BCSM_SGX
```

This repository uses the rust-sgx-sdk as a sub-module. The sub-module can be retrieved using the following command:
```
git submodule init
git submodule update
```

Then we modify the `run.sh` to change the `/home/ych/Research/2018Spring/CS294-144/` into your actual directory.

We can start the docker by:
```
chmod 0777 run.sh
sudo ./run.sh
```

Inside the docker, we go to `samplecode/BCSM_SGX`, run `make`, and go to `bin`. The demo program is `./app`.

## Acknowledgment

Weikeng would like to thank [Pratyush Mishra](http://people.eecs.berkeley.edu/~pratyushmishra/) for the discussion of semantically secure encryption schemes for multiple recipients with a single message. 
