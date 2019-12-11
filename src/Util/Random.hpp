#pragma once

#include <string>
#include <memory>
#include <cassert>
#include <chrono>

#include <openssl/rand.h>

namespace Random
{

std::string generate();

} // namespace Random
