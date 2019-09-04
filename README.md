# gardener-sgx-attestator

To build: `g++ main.cpp ra.a -I/opt/sgxsdk/include -L/usr/lib -lssl -lcrypto -o attestator`

Requires OpenSSL. ra.a is a static library built from gardener-sgx-enclave/Attestation/*.o that contains implementation of methods common for both sides of remote attestation process.

It also requires `IAS signing CA certificate` put it in `ias-cert.pem` in root dir.
