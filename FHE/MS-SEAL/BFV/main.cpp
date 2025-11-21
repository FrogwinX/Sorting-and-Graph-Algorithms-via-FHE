#include "seal/seal.h"
#include "bits/stdc++.h"
using namespace std;
using namespace seal;

vector<vector<Ciphertext>> vectorEncrypt(Encryptor &encryptor, vector<uint64_t> &v, size_t bitWidth, Plaintext &pZero, Plaintext &pOne) {
    cout << "Encrypting vector..." << endl;
    vector<vector<Ciphertext>> encryptedBitmap(v.size(), vector<Ciphertext>(bitWidth));
    for (int i=0; i<v.size(); i++) {
        for (int j=0; j<bitWidth; j++) {
            uint64_t bit = (v[i] >> j) & 1;
            cout << bit << " ";
            if (bit == 1) {
                encryptor.encrypt(pOne, encryptedBitmap[i][j]);
            } 
            else {
                encryptor.encrypt(pZero, encryptedBitmap[i][j]);
            }
        }
        cout << endl;
    }
    return encryptedBitmap;
}


vector<uint64_t> vectorDecrypt(Decryptor &decryptor, BatchEncoder &encoder, vector<vector<Ciphertext>> encryptedBitmap, size_t bitWidth) {
    cout << "Decrypting vector..." << endl;
    vector<uint64_t> v;
    for (int i=0; i<encryptedBitmap.size(); i++) {
        uint64_t num = 0;
        for (int j=bitWidth-1; j>=0; j--) {
            Plaintext p;
            decryptor.decrypt(encryptedBitmap[i][j], p);
            vector<uint64_t> result;
            encoder.decode(p, result);
            uint64_t bit = result[0];
            num = (num << 1) | bit;
        }
        v.push_back(num);
    }
    return v;
}

Ciphertext compare( 
    Evaluator &evaluator, 
    RelinKeys &relinKeys, 
    vector<Ciphertext> &num1, 
    vector<Ciphertext> &num2, 
    Ciphertext &cZero, Ciphertext &cOne
) {
    Plaintext pTwo("2");
    Ciphertext cLess = cZero;
    Ciphertext cEqual = cOne;

    for (int i=num1.size()-1; i>=0; i--) {
        Ciphertext a = num1[i];
        Ciphertext b = num2[i];

        Ciphertext currentLess;
        evaluator.sub(cOne, a, currentLess); // notA = 1 - a
        evaluator.multiply_inplace(currentLess, b); // notAAndB = (1 - a) * b
        evaluator.relinearize_inplace(currentLess, relinKeys);
        evaluator.multiply_inplace(currentLess, cEqual); // currentLess = (1 - a) * b * cEqual
        evaluator.relinearize_inplace(currentLess, relinKeys);

        Ciphertext plus, mul, diff;
        evaluator.add(cLess, currentLess, plus); // cLess + currentLess
        evaluator.multiply(cLess, currentLess, mul); // cLess * currentLess
        evaluator.relinearize_inplace(mul, relinKeys);
        evaluator.sub(plus, mul, diff); // diff = cLess + currentLess - cLess * currentLess
        cLess = diff;

        Ciphertext notXORAB, xorAB;
        evaluator.add(a, b, plus); // a + b
        evaluator.multiply(a, b, mul); // a * b
        evaluator.relinearize_inplace(mul, relinKeys);
        evaluator.multiply_plain_inplace(mul, pTwo); // 2 * a * b
  
        evaluator.sub(plus, mul, xorAB); // xorAB = a + b - 2 * a * b
        evaluator.sub(cOne, xorAB, notXORAB); // notXORAB = 1 - xorAB
        evaluator.multiply_inplace(cEqual, notXORAB);  // cEqual = cEqual * notXORAB
        evaluator.relinearize_inplace(cEqual, relinKeys);
    }

    return cLess;
}

pair<vector<Ciphertext>, vector<Ciphertext>> swap(  
    Evaluator &evaluator, 
    RelinKeys &relinKeys, 
    vector<Ciphertext> &num1, 
    vector<Ciphertext> &num2, 
    Ciphertext &less,
    Ciphertext &cOne
) {
    vector<Ciphertext> small(num1.size());
    vector<Ciphertext> large(num1.size());

    for (int i=0; i<num1.size(); i++) {
        Ciphertext a = num1[i];
        Ciphertext b = num2[i];
            
        Ciphertext notLess, first, second; 
        evaluator.sub(cOne, less, notLess);

        // small = (1 - less) * b + (less) * a
        evaluator.multiply(notLess, b, first);
        evaluator.relinearize_inplace(first, relinKeys);
        evaluator.multiply(less, a, second);
        evaluator.relinearize_inplace(second, relinKeys);
        evaluator.add(first, second, small[i]);
        
        // large = (1 - less) * a + (less) * b
        evaluator.multiply(notLess, a, first);
        evaluator.relinearize_inplace(first, relinKeys);
        evaluator.multiply(less, b, second);
        evaluator.relinearize_inplace(second, relinKeys);
        evaluator.add(first, second, large[i]);
    }

    return {small, large};
}

void bubbleSort(
    Encryptor &encryptor, 
    Evaluator &evaluator,         
    Decryptor &decryptor,      
    BatchEncoder &encoder,
    RelinKeys &relinKeys,
    vector<vector<Ciphertext>> &encryptedBitmap, 
    Ciphertext &cZero, Ciphertext &cOne
) {
    for (int i=0; i<encryptedBitmap.size()-1; i++) {
        for (int j=0; j<encryptedBitmap.size()-i-1; j++) {
            Ciphertext less = compare(evaluator, relinKeys, encryptedBitmap[j], encryptedBitmap[j+1], cZero, cOne);
            auto [small, large] = swap(evaluator, relinKeys, encryptedBitmap[j], encryptedBitmap[j+1], less, cOne);
            encryptedBitmap[j] = small;
            encryptedBitmap[j+1] = large;
        }
    }
}

void insertionSort( 
    Encryptor &encryptor,               
    Evaluator &evaluator, 
    Decryptor &decryptor,
    BatchEncoder &encoder,
    RelinKeys &relinKeys,
    vector<vector<Ciphertext>> &encryptedBitmap, 
    Ciphertext &cZero, Ciphertext &cOne
) {
    for (int i=1; i<encryptedBitmap.size(); i++) {
        for (int j=i-1; j>=0; j--) {
            Ciphertext less = compare(evaluator, relinKeys, encryptedBitmap[j], encryptedBitmap[j+1], cZero, cOne);
            auto [small, large] = swap(evaluator, relinKeys, encryptedBitmap[j], encryptedBitmap[j+1], less, cOne);
            encryptedBitmap[j] = small;
            encryptedBitmap[j+1] = large;
        }
    }
}


vector<uint64_t> runFHEJob(vector<uint64_t> v, size_t bitWidth=4) {
    // Define the encryption parameters
    size_t poly_modulus_degree = 32768;
    size_t bit_size = 20;
    int vectorSize = v.size();

    // Create SEALContext
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, bit_size));
    SEALContext context(parms);

    // Generate keys
    KeyGenerator keygen(context);
    SecretKey secretKey = keygen.secret_key();
    PublicKey publicKey;
    keygen.create_public_key(publicKey);
    RelinKeys relinKeys;
    keygen.create_relin_keys(relinKeys);

    // Create Encryptor, Decryptor, and Encoder
    Encryptor encryptor(context, publicKey);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secretKey);
    BatchEncoder encoder(context);

    Plaintext pZero("0");
    Plaintext pOne("1");

    Ciphertext cZero, cOne;
    encryptor.encrypt(pZero, cZero);
    encryptor.encrypt(pOne, cOne);

    vector<vector<Ciphertext>> encryptedBitmap = vectorEncrypt(encryptor, v, bitWidth, pZero, pOne);
    // bubbleSort(encryptor, evaluator, decryptor, encoder, relinKeys, encryptedBitmap, cZero, cOne);
    insertionSort(encryptor, evaluator, decryptor, encoder, relinKeys, encryptedBitmap, cZero, cOne);
    vector<u_int64_t> newV = vectorDecrypt(decryptor, encoder, encryptedBitmap, bitWidth);
    return newV;
}

int main() {
    size_t bitWidth;
    uint64_t n, num;
    vector<uint64_t> unsorted;
    cout << "BitWidth?: ";
    cin >> bitWidth;
    cout << "Number of elements?: ";
    cin >> n;
    cout << "Elements?: " << endl;
    while (n) {
        cin >> num;
        unsorted.push_back(num);
        n--;
    }

    cout << "Unsorted array: ";
    for (int i=0; i<unsorted.size(); i++) {
        cout << unsorted.at(i) << " ";
    }
    cout << endl;
    
    vector<uint64_t> sorted = runFHEJob(unsorted, bitWidth);
    cout << "Sorted array: ";
    for (int i=0; i<sorted.size(); i++) {
        cout << sorted.at(i) << " ";
    }
    cout << endl;

    return 0;
}
