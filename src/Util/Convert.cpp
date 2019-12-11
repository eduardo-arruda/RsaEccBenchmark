#include "Convert.hpp"

namespace Convert
{

std::string ByteVectorToHexString(std::vector<unsigned char> byteVector)
{
  std::ostringstream hexString;
  hexString << std::hex << std::uppercase << std::setfill('0');
  for(int c : byteVector) {
    hexString << std::setw(2) << c;
  }
  return hexString.str();
}

std::vector<unsigned char> HexStringToByteVector(std::string hexString)
{
  std::istringstream hexStringStream(hexString);
  std::vector<unsigned char> byteVector;
  unsigned int c;
  while(hexStringStream >> std::hex >> c) {
    byteVector.push_back(c);
  }
  return byteVector;
}

} // namespace Convert
