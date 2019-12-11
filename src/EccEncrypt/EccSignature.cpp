#include "EccSignature.hpp"

#include <openssl/err.h>

namespace EccEncrypt
{

std::string Signature::getValue()
{
  return this->value;
}

std::vector<unsigned char> Signature::getSignature()
{
  return this->signature;
}

std::string Signature::getSignatureAsString()
{
  return Convert::ByteVectorToHexString(this->signature);
}

void Signature::create(std::string value, EccEncrypt::BioPtr privateKeyBio)
{
  int errorCode;

  this->value = value;

  EccEncrypt::KeyPtr privateKey(PEM_read_bio_ECPrivateKey(privateKeyBio.get(), nullptr, nullptr, nullptr), &::EC_KEY_free);

  unsigned char buffer[SHA256_DIGEST_LENGTH];
  this->signature = std::vector<unsigned char>(ECDSA_size(privateKey.get()));
  this->signatureLength = 0;
  errorCode = ECDSA_sign(NID_sha256, SHA256(reinterpret_cast<const unsigned char *>(this->value.c_str()), this->value.length(), buffer), SHA256_DIGEST_LENGTH, this->signature.data(), &(this->signatureLength), privateKey.get());
  assert(errorCode == 1);
}

bool Signature::verify(EccEncrypt::BioPtr publicKeyBio)
{
  int verifyState;

  EccEncrypt::KeyPtr publicKey(PEM_read_bio_EC_PUBKEY(publicKeyBio.get(), nullptr, nullptr, nullptr), &::EC_KEY_free);
  unsigned char buffer[SHA256_DIGEST_LENGTH];
  verifyState = ECDSA_verify(NID_undef, SHA256(reinterpret_cast<const unsigned char *>(this->value.c_str()), this->value.length(), buffer), SHA256_DIGEST_LENGTH, this->signature.data(), this->signatureLength, publicKey.get());
  assert(verifyState == 1);
  return true;
}

} // namespace EccEncrypt
