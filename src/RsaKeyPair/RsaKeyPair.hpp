#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <cassert>
#include <chrono>
#include <map>

#include <openssl/bn.h>
using BigNumberPtr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
#include <openssl/rsa.h>
using RsaKeyPairPtr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
#include <openssl/bio.h>
using BioPtr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
#include <openssl/pem.h>

#include "spdlog.h"
#include "sinks/basic_file_sink.h"

namespace RsaEncrypt
{

enum class KeySize : int
{
  RSA2048 = 2048,
  RSA4096 = 4096
};

inline std::map<KeySize, std::string> keySizes = {
    {KeySize::RSA2048, "2048 bits"},
    {KeySize::RSA4096, "4096 bits"}};

class KeyPair
{
private:
  RsaKeyPairPtr rsaKeyPairPtr;
  KeySize keySize;

public:
  KeyPair(KeyPair const &) = delete; //Disable copies
  KeyPair(KeySize const keySize);

  std::string getPrivateKey();
  std::string getPublicKey();
};

} // namespace RsaEncrypt
