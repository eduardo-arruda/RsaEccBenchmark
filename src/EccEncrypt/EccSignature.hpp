#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <cassert>

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "Convert.hpp"

#include "EccKeyPair.hpp"

namespace EccEncrypt
{

class Signature
{
private:
  std::string value;
  std::vector<unsigned char> signature;
  unsigned int signatureLength;

public:
  std::string getValue();
  std::vector<unsigned char> getSignature();
  std::string getSignatureAsString();

  void create(std::string value, EccEncrypt::BioPtr privateKeyBio);
  bool verify(EccEncrypt::BioPtr publicKeyBio);
};

} // namespace EccEncrypt