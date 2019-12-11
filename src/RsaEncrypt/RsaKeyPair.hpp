#pragma once

#include <string>
#include <memory>
#include <cassert>
#include <chrono>
#include <map>
#include <iostream>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "spdlog.h"
#include "sinks/basic_file_sink.h"

namespace RsaEncrypt
{

using KeyPtr = std::shared_ptr<RSA>;
using BioPtr = std::shared_ptr<BIO>;
using BigNumberPtr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

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
  KeyPtr keyPairPtr;
  KeySize keySize;

public:
  KeyPair(KeySize const keySize);

  KeyPtr getKeyPair();
  BioPtr getPrivateKey();
  std::string getPrivateKeyPem();
  BioPtr getPublicKey();
  std::string getPublicKeyPem();
};

} // namespace RsaEncrypt
