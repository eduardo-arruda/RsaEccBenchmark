#include "EccKeyPair.hpp"

namespace EccEncrypt
{

KeyPair::KeyPair(Curve const curve) : eccKeyPairPtr(EC_KEY_new_by_curve_name(static_cast<int>(curve)), ::EC_KEY_free)
{
  int error_code;

  // Generate ECC keypair
  auto timestampBegin = std::chrono::steady_clock::now();
  error_code = EC_KEY_generate_key(this->eccKeyPairPtr.get());
  auto timestampEnd = std::chrono::steady_clock::now();
  assert(error_code == 1);
  auto elapsedTime = std::chrono::duration_cast<std::chrono::nanoseconds>(timestampEnd - timestampBegin).count();
  std::cout << "Elapsed time: " << elapsedTime << "ns" << std::endl;
  this->curve = curve;
}

std::string KeyPair::getPrivateKey()
{
  int error_code;

  // Get private key
  BioPtr bioPrivateKey(BIO_new(BIO_s_mem()), ::BIO_free);
  error_code = PEM_write_bio_ECPrivateKey(bioPrivateKey.get(), this->eccKeyPairPtr.get(), NULL, NULL, 0, NULL, NULL);
  assert(error_code == 1);

  // Convert private key to PEM format string
  int bioPrivateKeyLenght = BIO_pending(bioPrivateKey.get());
  void *privateKey = calloc(bioPrivateKeyLenght + 1, 1);
  error_code = BIO_read(bioPrivateKey.get(), privateKey, bioPrivateKeyLenght);
  assert(error_code > 1);

  return std::string(static_cast<char *>(privateKey));
};

std::string KeyPair::getPublicKey()
{
  int error_code;

  // Get private key
  BioPtr bioPublicKey(BIO_new(BIO_s_mem()), ::BIO_free);
  error_code = PEM_write_bio_EC_PUBKEY(bioPublicKey.get(), this->eccKeyPairPtr.get());
  assert(error_code == 1);

  // Convert private key to PEM format string
  int bioPublicKeyLenght = BIO_pending(bioPublicKey.get());
  char *publicKey = static_cast<char *>(calloc(bioPublicKeyLenght + 1, 1));
  error_code = BIO_read(bioPublicKey.get(), publicKey, bioPublicKeyLenght);
  assert(error_code > 1);

  return std::string(publicKey);
};

} // namespace EccEncrypt
