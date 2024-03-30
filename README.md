# Kyber.PAKE
To obtain the password-authenticated version of Kyber KEM, the one-phase PAK design approach, which provides explicit authentication and PFS, is followed. The KYBER.CCAKEM.KeyGen, KYBER.CCAKEM.Enc, and KYBER.CCAKEM.Dec structures, are used for key generation, encapsulation, and decapsulation. By using these functions, the idea of PAK is added to achieve password-based authentication. Thanks to the MLWE-based PAK and Kyber structures, two-way authentication is obtained. The proposed Kyber.PAKE contains four main sub-phases (C0, S0, C1, and S1) and three flows

### Related Paper
Please cite the following papers, if you use the code as part of your research

Seyhan K, Akleylek S, Dursun AF. 2024. Password authenticated key exchange-based on Kyber for mobile devices. PeerJ Computer Science 10:e1960 https://doi.org/10.7717/peerj-cs.1960

## Usage

#### Test

```c
Testing all versions = make all
Kyber512.PAKE = make pake_kyber512
Kyber768.PAKE = make pake_kyber768
Kyber1024.PAKE = make pake_kyber1024
```


#### Speed-Test

```c
Kyber512.PAKE = make test_speed512
Kyber768.PAKE = make test_speed768
Kyber1024.PAKE = make test_speed1024
```


## Acknowledgment

- This research was partially supported by TUBITAK under Grant No. 121R006

  
