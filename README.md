# gardener-sgx-attestator

A client used in remote attestation process.

To build: `g++ main.cpp ra.a -I/opt/sgxsdk/include -L/usr/lib -lssl -lcrypto -o attestator`

Requires OpenSSL. `ra.a` is a static library built from `gardener-sgx-enclave/Attestation/*.o` that contains implementation of methods common for both sides of remote attestation process.

Querying Intel Attestation Service requires `IAS signing CA certificate`. Put it in `ias-cert.pem` in root dir. It also requires a linked EPID Attestation account: https://api.portal.trustedservices.intel.com/EPID-attestation - it is necessary to configure `gardener-sgx-attestator` with SPID and both primary&secondary subscription keys acquired from there.
