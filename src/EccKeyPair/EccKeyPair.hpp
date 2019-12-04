#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <cassert>
#include <chrono>
#include <map>

#include <openssl/bn.h>
using BigNumberPtr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
#include <openssl/ec.h>
using EccKeyPairPtr = std::unique_ptr<EC_KEY, decltype(&::EC_KEY_free)>;
#include <openssl/bio.h>
using BioPtr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
#include <openssl/pem.h>

#include "spdlog.h"
#include "sinks/basic_file_sink.h"

namespace EccEncrypt
{

enum class Curve : int
{
  secp224r1 = NID_secp224r1,
  secp256k1 = NID_secp256k1,
  secp384r1 = NID_secp384r1,
  secp521r1 = NID_secp521r1
};

inline std::map<Curve, std::string> curves = {
    {Curve::secp224r1, "curve secp224r1"},
    {Curve::secp256k1, "curve secp256k1"},
    {Curve::secp384r1, "curve secp384r1"},
    {Curve::secp521r1, "curve secp521r1"}};

class KeyPair
{
private:
  EccKeyPairPtr eccKeyPairPtr;
  Curve curve;

public:
  KeyPair(KeyPair const &) = delete; //Disable copies
  KeyPair(Curve const curve);

  std::string getPrivateKey();
  std::string getPublicKey();
};

} // namespace EccEncrypt
