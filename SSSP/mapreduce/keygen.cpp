#include "tfhe_helper.h"

int main(int argc, char* argv[]) {
    BinFHEContext cc;
    LWEPrivateKey sk;
    LWECiphertext cZero;
    cc.GenerateBinFHEContext(STD128_LMKCDEY, LMKCDEY);
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    cZero = cc.Encrypt(sk, 0, FRESH, 4);

    Serial::SerializeToFile("cc.bin", cc, SerType::BINARY);
    Serial::SerializeToFile("sk.bin", sk, SerType::BINARY);
    Serial::SerializeToFile("czero.bin", cZero, SerType::BINARY);
    Serial::SerializeToFile("btkey.bin", cc.GetRefreshKey(), SerType::BINARY);
    Serial::SerializeToFile("kskey.bin", cc.GetSwitchKey(), SerType::BINARY);
    return 0;
}