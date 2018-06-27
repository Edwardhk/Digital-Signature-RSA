# RSA Digital Signature with libressl


## Installation

Clone the repository

`$ git clone https://github.com/Edwardhk/Digital-Signature-RSA.git`

Install the libressl using the `setup.sh`

`$ ./setup.sh`

Then compile the `main.c` by

`$ ./gen_rsa_key.sh`

## Functions list

| Return    | Function_name             | Usage |
| --------- |:-------------             | -----|
| bool      | `rsa_sign()`              | Takes RSA* and original msg, returns signed msg and its length |
| void      | `base_64_encode()`        | Takes msg and length, returns base64 encoded msg |
| char*     | `write_rsa_to_char()`     | Takes RSA* and write it to printable char* |



