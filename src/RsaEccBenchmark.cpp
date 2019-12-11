#include <iostream>
#include <string>
#include <map>
#include <exception>
#include <openssl/rand.h>

#include "Convert.hpp"
#include "Base64.hpp"
#include "Random.hpp"
#include "RsaKeyPair.hpp"
#include "RsaSignature.hpp"
#include "EccKeyPair.hpp"
#include "EccSignature.hpp"

int main(int, char **)
{
  std::cout << "RSA x ECC Benchmark" << std::endl << std::endl; // << rsa_ecc_benchmark_VERSION_MAJOR << "." << rsa_ecc_benchmark_VERSION_MINOR
  try
  {
    std::string randomNumber = Base64::encode(Random::generate());
    std::cout << "randomNumber =" << std::endl << randomNumber << std::endl << std::endl;
    for (auto keySize : RsaEncrypt::keySizes)
    {
      RsaEncrypt::KeyPair rsaKeyPair(keySize.first);
      std::cout << rsaKeyPair.getPrivateKeyPem() << std::endl;
      std::cout << rsaKeyPair.getPublicKeyPem() << std::endl;
      RsaEncrypt::Signature rsaSignature;
      rsaSignature.create(randomNumber, rsaKeyPair.getPrivateKey());
      std::cout << "signedRandomNumber = " << rsaSignature.getSignatureAsString() << std::endl << std::endl;
      bool rsaSignatureVerify = rsaSignature.verify(rsaKeyPair.getPublicKey());
      std::cout << "signedRandomNumber verify = " << rsaSignatureVerify << std::endl << std::endl; 
    }
    for (auto curve : EccEncrypt::curves)
    {
      EccEncrypt::KeyPair eccKeyPair(curve.first);
      std::cout << eccKeyPair.getPrivateKeyPem() << std::endl;
      std::cout << eccKeyPair.getPublicKeyPem() << std::endl;
      EccEncrypt::Signature eccSignature;
      eccSignature.create(randomNumber, eccKeyPair.getPrivateKey());
      std::cout << "signedRandomNumber = " << eccSignature.getSignatureAsString() << std::endl << std::endl;
      bool eccSignatureVerify = eccSignature.verify(eccKeyPair.getPublicKey());
      std::cout << "signedRandomNumber verify = " << eccSignatureVerify << std::endl << std::endl; 
    }
  }
  catch (const std::exception& e)
  {
  }
}
