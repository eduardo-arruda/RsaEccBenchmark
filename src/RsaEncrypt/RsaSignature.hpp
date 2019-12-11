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
#include "RsaKeyPair.hpp"

namespace RsaEncrypt
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

  void create(std::string value, RsaEncrypt::BioPtr privateKeyBio);
  bool verify(RsaEncrypt::BioPtr publicKeyBio);
};

} // namespace RsaEncrypt
