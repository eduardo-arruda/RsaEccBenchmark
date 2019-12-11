#include <cstring>

#include "Base64.hpp"

namespace Base64
{

std::string encode(std::string value)
{
  int errorCode;

  BIO *base64, *bioBuffer;
  BUF_MEM *bufferPtr;

  base64 = BIO_new(BIO_f_base64());
  bioBuffer = BIO_new(BIO_s_mem());
  base64 = BIO_push(base64, bioBuffer); 
  BIO_write(base64, value.data(), value.length());
  BIO_flush(base64);
  BIO_get_mem_ptr(base64, &bufferPtr);

  char *strBuffer = (char *)malloc(bufferPtr->length);
  memcpy(strBuffer, bufferPtr->data, bufferPtr->length-1);
  strBuffer[bufferPtr->length-1] = 0;
 
  BIO_free_all(base64);

  return std::string((char *)strBuffer);
}

std::string decode(std::string value)
{
  int errorCode;

  BIO *base64, *bioBuffer;
 
  char *strBuffer = (char *)malloc(value.length());
  memset(strBuffer, 0, value.length());
 
  base64 = BIO_new(BIO_f_base64());
  bioBuffer = BIO_new_mem_buf(value.data(), value.length());
  bioBuffer = BIO_push(base64, bioBuffer);
 
  BIO_read(bioBuffer, strBuffer, value.length());
 
  BIO_free_all(bioBuffer);
 
  return std::string((char *)strBuffer);
}

} // namespace Base64
