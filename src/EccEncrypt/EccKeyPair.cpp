#include "EccKeyPair.hpp"

namespace EccEncrypt
{

KeyPair::KeyPair(Curve const curve) : keyPairPtr(EC_KEY_new_by_curve_name(static_cast<int>(curve)), &::EC_KEY_free)
{
  int errorCode;

  // Generate ECC keypair
  auto timestampBegin = std::chrono::steady_clock::now();
  errorCode = EC_KEY_generate_key(this->keyPairPtr.get());
  auto timestampEnd = std::chrono::steady_clock::now();
  assert(errorCode == 1);
  auto elapsedTime = std::chrono::duration_cast<std::chrono::nanoseconds>(timestampEnd - timestampBegin).count();

  std::cout << "Elapsed time: " << elapsedTime << "ns" << std::endl;
  this->curve = curve;
}

KeyPtr KeyPair::getKeyPair()
{
  return this->keyPairPtr;
}

BioPtr KeyPair::getPrivateKey()
{
  int errorCode;

  BioPtr privateKey(BIO_new(BIO_s_mem()), &::BIO_free);
  errorCode = PEM_write_bio_ECPrivateKey(privateKey.get(), this->keyPairPtr.get(), NULL, NULL, 0, NULL, NULL);
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
  errorCode = PEM_write_bio_EC_PUBKEY(publicKey.get(), this->keyPairPtr.get());
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

} // namespace EccEncrypt
