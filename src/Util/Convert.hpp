#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

namespace Convert
{

std::string ByteVectorToHexString(std::vector<unsigned char> byteVector);
std::vector<unsigned char> HexStringToByteVector(std::string hexString);

} // namespace Convert
