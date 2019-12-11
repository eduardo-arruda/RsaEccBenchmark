#include "RsaSignature.hpp"

namespace RsaEncrypt
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

void Signature::create(std::string value, RsaEncrypt::BioPtr privateKeyBio)
{
  int errorCode;

  this->value = value;

  RsaEncrypt::KeyPtr privateKey(PEM_read_bio_RSAPrivateKey(privateKeyBio.get(), nullptr, nullptr, nullptr), &::RSA_free);

  unsigned char buffer[SHA256_DIGEST_LENGTH];
  this->signature = std::vector<unsigned char>(RSA_size(privateKey.get()));
  this->signatureLength = 0;
  errorCode = RSA_sign(NID_sha256, SHA256(reinterpret_cast<const unsigned char *>(this->value.c_str()), this->value.length(), buffer), SHA256_DIGEST_LENGTH, this->signature.data(), &(this->signatureLength), privateKey.get());
  assert(errorCode == 1);
}

bool Signature::verify(RsaEncrypt::BioPtr publicKeyBio)
{
  int verifyState;

  RsaEncrypt::KeyPtr publicKey(PEM_read_bio_RSA_PUBKEY(publicKeyBio.get(), nullptr, nullptr, nullptr), &::RSA_free);
  unsigned char buffer[SHA256_DIGEST_LENGTH];
  verifyState = RSA_verify(NID_sha256, SHA256(reinterpret_cast<const unsigned char *>(this->value.c_str()), this->value.length(), buffer), SHA256_DIGEST_LENGTH, this->signature.data(), this->signatureLength, publicKey.get());
  assert(verifyState == 1);
  return true;
}

} // namespace RsaEncrypt
