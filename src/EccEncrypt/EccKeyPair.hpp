#pragma once

#include <string>
#include <memory>
#include <cassert>
#include <chrono>
#include <map>
#include <iostream>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "spdlog.h"
#include "sinks/basic_file_sink.h"

namespace EccEncrypt
{

using KeyPtr = std::shared_ptr<EC_KEY>;
using BioPtr = std::shared_ptr<BIO>;
using BigNumberPtr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

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
  KeyPtr keyPairPtr;
  Curve curve;

public:
  KeyPair(Curve const curve);

  KeyPtr getKeyPair();
  BioPtr getPrivateKey();
  std::string getPrivateKeyPem();
  BioPtr getPublicKey();
  std::string getPublicKeyPem();
};

} // namespace EccEncrypt
