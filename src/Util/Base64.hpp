#pragma once

#include <string>
#include <cassert>

#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

namespace Base64
{

std::string encode(std::string value);
std::string decode(std::string value);

} // namespace Base64
