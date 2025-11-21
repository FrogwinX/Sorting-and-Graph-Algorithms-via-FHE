#include "seal/seal.h"
#include <iostream>
using namespace std;
using namespace seal;

int main() {
    // Define the encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create SEALContext
    SEALContext context(parms);

    // Generate sk, pk
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);

    // Create tools
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    // Encryption
    Plaintext p1("E"), p2("A");
    Ciphertext c1, c2, c3, cSum;
    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    // Addition
    evaluator.negate(c2, c3);
    evaluator.add(c1, c3, cSum);

    // Decryption
    Plaintext hex_result;
    decryptor.decrypt(cSum, hex_result);

    int dec_result;
    stringstream ss(hex_result.to_string());
    ss >> hex >> dec_result;
    cout << "Decrypted sum: " << dec_result << endl;

    return 0;
}
