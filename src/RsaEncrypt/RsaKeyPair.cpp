#include "RsaKeyPair.hpp"

namespace RsaEncrypt
{

KeyPair::KeyPair(KeySize const keySize) : keyPairPtr(RSA_new(), &::RSA_free)
{
  int errorCode;

  // Generate RSA exponent
  BigNumberPtr bigNumberPtr(BN_new(), &::BN_free);
  errorCode = BN_set_word(bigNumberPtr.get(), RSA_F4);
  assert(errorCode == 1);

  // Generate RSA keypair
  auto timestampBegin = std::chrono::steady_clock::now();
  errorCode = RSA_generate_key_ex(this->keyPairPtr.get(), static_cast<int>(keySize), bigNumberPtr.get(), NULL);
  auto timestampEnd = std::chrono::steady_clock::now();
  assert(errorCode == 1);
  auto elapsedTime = std::chrono::duration_cast<std::chrono::nanoseconds>(timestampEnd - timestampBegin).count();

  this->keySize = keySize;
}

KeyPtr KeyPair::getKeyPair()
{
  return this->keyPairPtr;
}

BioPtr KeyPair::getPrivateKey()
{
  int errorCode;

  BioPtr privateKey(BIO_new(BIO_s_mem()), &::BIO_free);
  errorCode = PEM_write_bio_RSAPrivateKey(privateKey.get(), this->keyPairPtr.get(), NULL, NULL, 0, NULL, NULL);
  assert(errorCode == 1);

  return privateKey;
};

std::string KeyPair::getPrivateKeyPem()
{
  int errorCode;

  int privateKeyLenght = BIO_pending(this->getPrivateKey().get());
  char *privateKey = static_cast<char *>(calloc(privateKeyLenght + 1, 1));
  errorCode = BIO_read(this->getPrivateKey().get(), privateKey, privateKeyLenght);
  assert(errorCode > 1);

  return std::string(privateKey);
};

BioPtr KeyPair::getPublicKey()
{
  int errorCode;

  BioPtr publicKey(BIO_new(BIO_s_mem()), &::BIO_free);
  errorCode = PEM_write_bio_RSA_PUBKEY(publicKey.get(), this->keyPairPtr.get());
  assert(errorCode == 1);

  return publicKey;
};

std::string KeyPair::getPublicKeyPem()
{
  int errorCode;

  int publicKeyLenght = BIO_pending(this->getPublicKey().get());
  char *publicKey = static_cast<char *>(calloc(publicKeyLenght + 1, 1));
  errorCode = BIO_read(this->getPublicKey().get(), publicKey, publicKeyLenght);
  assert(errorCode > 1);

  return std::string(publicKey);
};

} // namespace RsaEncrypt
