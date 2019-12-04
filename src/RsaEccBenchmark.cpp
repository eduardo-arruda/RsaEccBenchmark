#include <iostream>
#include <string>
#include <map>
#include <exception>

#include "EccKeyPair.hpp"
#include "RsaKeyPair.hpp"

int main(int, char **)
{
  std::cout << "RSA x ECC Benchmark - Version "; // << rsa_ecc_benchmark_VERSION_MAJOR << "." << rsa_ecc_benchmark_VERSION_MINOR << std::endl;
  try
  {
    for (auto keySize : RsaEncrypt::keySizes)
    {
      RsaEncrypt::KeyPair rsaKeypair = RsaEncrypt::KeyPair(keySize.first);
      std::cout << "RSA " << keySize.second << std::endl;
      std::cout << rsaKeypair.getPrivateKey() << std::endl;
      std::cout << rsaKeypair.getPublicKey() << std::endl;
    }
    for (auto curve : EccEncrypt::curves)
    {
      EccEncrypt::KeyPair eccKeypair = EccEncrypt::KeyPair(curve.first);
      std::cout << "ECC " << curve.second << std::endl;
      std::cout << eccKeypair.getPrivateKey() << std::endl;
      std::cout << eccKeypair.getPublicKey() << std::endl;
    }
  }
  catch (const std::exception& e)
  {
  }
}
