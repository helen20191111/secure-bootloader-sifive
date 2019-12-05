# secure-bootloader-sifive
The purpose of a "secure" bootloader is to ensure that first software to be run on platform is the one expected.

## Documents
In this folder is gathered short documentations about Secure Boot ROM part of Secure Bootloader.

* [SecureBoot-Introduction.pdf](https://github.com/sifive/secure-bootloader-sifive/blob/master/Documents/SecureBoot-Introduction.pdf): Secure Bootloader introduction.
* [SecureBoot-SBR.pdf](https://github.com/sifive/secure-bootloader-sifive/blob/master/Documents/SecureBoot-SBR.pdf) : Secure Boot ROM features.
* [SecureBoot-SUP.pdf](https://github.com/sifive/secure-bootloader-sifive/blob/master/Documents/SecureBoot-SUP.pdf) : Description of Secure Update Protocol implemented in SBR.
* [SecureBoot-SLB.pdf](https://github.com/sifive/secure-bootloader-sifive/blob/master/Documents/SecureBoot-SLB.pdf) : Short description and SLB checking and launching.
* [SecureBoot_OTP_mapping.pdf](https://github.com/sifive/secure-bootloader-sifive/blob/master/Documents/SecureBoot-OTP_mappin.pdf) : Basic mapping of SBR parameters in OTP.

## Secure Boot ROM
This repository only presents source code of Secure Boot ROM for ***mono-core platforms***. Having Multi-cores Secure Boot ROM induces other mechanisms/architecture not introduced in this delivery.


## Secure Flexible Loader
This source repository shows simplest sifive's implementation of Second Level Bootloader. Note that customer can implement its own, or use U-Boot; but this SLB is more specific to platform.
For instance, it's where clocks/PLLs are set to match customer application needs, or any end user's considerations.
Whatever the origin of this SLB, it has to be formatted as SBR expect to be granted for execution.