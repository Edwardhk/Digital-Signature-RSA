# RSA Digital Signature with libressl


## Installation

Clone the repository

`$ git clone https://github.com/Edwardhk/Digital-Signature-RSA.git`

Install the libressl using the `setup.sh`

`$ ./setup.sh`

Then compile the `main.c` by

`$ ./gen_rsa_key.sh`

</br>

## Functions list

| Return    | Function_name             | Usage |
| --------- |:-------------             | -----|
| bool      | `rsa_sign()`              | Takes RSA* and original msg, returns signed msg and its length |
| void      | `base_64_encode()`        | Takes msg and length, returns base64 encoded msg |
| char*     | `get_private_char()`      | Takes RSA*, returns private key char* |
| char*     | `get_public_char()`       | Takes RSA*, returns public key char* |

</br>

## Main flow

| Device                  | Action|
| ---------               | -----|
| Client                  | Generate `private_key` & `public_key`|
| Host                    | Receive `public_key`|
| Host                    | Sign the message with `public_key`|
| Host                    | Encode signed message in base64 format|
| Client                  | Decode the base64 format message|
| Client                  | Decrypt the message with `private_key`|

