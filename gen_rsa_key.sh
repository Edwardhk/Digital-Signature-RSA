# Compile the source file
gcc -std=c11 main.c -lcrypto -o gen_rsa_key

# Run the output
./gen_rsa_key