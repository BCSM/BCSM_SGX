# An Intel SGX Encryption and Signing Oracle

This repository is for an [Intel SGX](https://software.intel.com/en-us/sgx) encryption and signing oracle with the application to blockchain-based controlled substances monitoring.

This is part of the implementation for a course project to [CS294-144](https://berkeley-blockchain.github.io/cs294-144-s18/), Blockchain, Cryptoeconomics, and the Future of Technology, Business and Law. 

The implementation is based on [Baidu's Rust SGX SDK](https://github.com/baidu/rust-sgx-sdk).

**Author:** Yuncong Hu, UC Berkeley. 

**Acknowledgment:** Weikeng Chen, UC Berkeley.

## Motivation
We consider a world with digital prescription (Rx). There are mainly six parties as follows:
- **Doctor:** 
  - *Encryption:* A doctor uses the patient's ID (such as the combinition of patient's name, birthday and SSN) to encrypt the Rx. Also a doctor must also encrypt patient's ID using federal government's and corresponding state government's public encryption key so that governments can monitor those Rxs.
  - *Signing:* A doctor has a pair of signing key *SK* and *VK*. The doctor commits the *VK*	to a key transparency system, like [CONIKS](https://github.com/coniks-sys/coniks-go). The doctor uses *SK* to sign a Rx. When a Rx is signed by a doctor with valid license (namely, *VK* is active in CONIKS), the Rx becomes valid. 
- **State Board of Medicine:** The *State Board of Medicine* uses CONIKS to manage doctors' *VK* and is responsible to anounce revoked *VK*.
- **Miner:** A signed Rx will be sent to the miner and stored on the permissioned blockchain like [Hyperledger Fabric](https://www.hyperledger.org/projects/fabric). Miner gets the doctor's *VK* from CONIKS and checks whether the signature is valid (although on-chain Rx should already have a valid doctor signature). If the signature is valid, the Rx will be settled on blockchain.
- **Patient:** A patient goes to a doctor for a digital Rx. The patient then brings the digital Rx to the pharmacy to pick up the medicine. In our course project, we focus on controlled substances.
- **Pharmacy:** A pharmacy sells prescripted medicine under a doctor's Rx. A pharmacy downloads the Rx from blockchain.  
- **Government:** A federal government is able to decrypt all Rxs on blockchain, whereas a state government can only monitor Rxs within the state.

Now, we consider an adversary:
- **Adversary:** An adversary wants to order controlled substances from government approved pharmacies (with the market price) and sells in the underground market. In order to get controlled substances from the pharmacies, the adversary needs to obtain many valid Rx. 
  - *Inconsistent encryption attack:* A Rx will be encrypted under patient's, state government's, and federal government's encryption key. A compromised doctor may provide different encrypted Rx to different parties. The miner cannot detect the inconsistency immediately without government's key which may leak the patient's information.
  - *Key stealing attack:* The doctor may leak signing key and the adversary may steal doctor's signing key to sign whatever Rx it wants.

We want to design a encryption and signing oracle resilient to inconsistent encryption attack and key stealing attacks. It has following properties:
- *Encryption:*
  - The encryption process is easily verifable so that Rx will be correctly encrypted under different encryption key.
- *Signing:*
  - The doctor can use this oracle to sign a piece of message that is generated honestly, possibly with two-factor authentication like a [FIDO U2F](https://www.yubico.com/solutions/fido-u2f/).
  - There is no easy way to extract the signing key.

## The idea, at a high level

To build a encryption and signing oracle resilient to those two attacks, we need to generate a proof for the encryption process and defend against computer viruses that may compromise the whole software stack.

We use Intel SGX (Software Guard Extensions), a platform to build secure applications that only trust Intel. We make use of the following three properties of Intel SGX:
- *Remote attestation:* A remote party can attest whether the correct code is running in the Intel SGX and establish a secure communication channel.
- *Sealing:* For the same application, Intel SGX provides a unique key that remain the same even if the machine reboots. We can use this key with authenticated encryption to seal a secret that only this application (on this machine) can read.
- *Isolation:* The application runs in an isolation environment that even the operating system cannot access the memory of the protected application.

In this application, the enclave will generate the signing key *SK* and the verifying key *VK*. The verifying key will leave the enclave and be sent to *State Board of Medicine*, but the signing key is sealed and never leave the enclave. The *State Board of Medicine* is also responsible to remote attest the doctor's enclave to ensure honest encryption. Later, the doctor can use the enclave program to encrypt and sign an Rx.

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

We can start the docker by:
```
chmod 0777 run.sh
sudo ./run.sh
```

Inside the docker, first we runs the AESM service:
```
/opt/intel/sgxpsw/aesm/aesm_service &
```

Then we go to `samplecode/BCSM_SGX`, run `make`, and go to `bin`. The demo program is `./app`.

## Acknowledgment

Weikeng would like to thank [Pratyush Mishra](http://people.eecs.berkeley.edu/~pratyushmishra/) for the discussion of semantically secure encryption schemes for multiple recipients with a single message. 
