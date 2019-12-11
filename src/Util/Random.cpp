#include "Random.hpp"
#include "Base64.hpp"

namespace Random
{

std::string generate()
{
  int errorCode;

  unsigned char buffer[128];
  int count;

  errorCode = RAND_bytes(buffer, sizeof(buffer));
  assert(errorCode == 1);

  return std::string((char *)buffer);
}

} // namespace Random
