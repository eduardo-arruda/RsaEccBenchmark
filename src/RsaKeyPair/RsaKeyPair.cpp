#include "RsaKeyPair.hpp"

namespace RsaEncrypt
{

KeyPair::KeyPair(KeySize const keySize) : rsaKeyPairPtr(RSA_new(), ::RSA_free)
{
  int error_code;

  // Generate RSA exponent
  BigNumberPtr bigNumberPtr(BN_new(), ::BN_free);
  error_code = BN_set_word(bigNumberPtr.get(), RSA_F4);
  assert(error_code == 1);

  // Generate RSA keypair
  auto timestampBegin = std::chrono::steady_clock::now();
  error_code = RSA_generate_key_ex(this->rsaKeyPairPtr.get(), static_cast<int>(keySize), bigNumberPtr.get(), NULL);
  auto timestampEnd = std::chrono::steady_clock::now();
  assert(error_code == 1);
  auto elapsedTime = std::chrono::duration_cast<std::chrono::nanoseconds>(timestampEnd - timestampBegin).count();
  std::cout << "Elapsed time: " << elapsedTime << "ns" << std::endl;
  this->keySize = keySize;
}

std::string KeyPair::getPrivateKey()
{
  int error_code;

  // Get private key
  BioPtr bioPrivateKey(BIO_new(BIO_s_mem()), ::BIO_free);
  error_code = PEM_write_bio_RSAPrivateKey(bioPrivateKey.get(), this->rsaKeyPairPtr.get(), NULL, NULL, 0, NULL, NULL);

  // Convert private key to PEM format string
  int bioPrivateKeyLenght = BIO_pending(bioPrivateKey.get());
  char *privateKey = static_cast<char *>(calloc(bioPrivateKeyLenght + 1, 1));
  error_code = BIO_read(bioPrivateKey.get(), privateKey, bioPrivateKeyLenght);
  assert(error_code > 1);

  return std::string(privateKey);
};

std::string KeyPair::getPublicKey()
{
  int error_code;

  // Get private key
  BioPtr bioPublicKey(BIO_new(BIO_s_mem()), ::BIO_free);
  error_code = PEM_write_bio_RSAPublicKey(bioPublicKey.get(), this->rsaKeyPairPtr.get());

  // Convert private key to PEM format string
  int bioPublicKeyLenght = BIO_pending(bioPublicKey.get());
  char *publicKey = static_cast<char *>(calloc(bioPublicKeyLenght + 1, 1));
  error_code = BIO_read(bioPublicKey.get(), publicKey, bioPublicKeyLenght);
  assert(error_code > 1);

  return std::string(publicKey);
};

} // namespace RsaEncrypt
