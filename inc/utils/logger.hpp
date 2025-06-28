#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "../crypto/ec.hpp"
#include <openssl/bn.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <print>

#define PARAM_BN 0
#define PARAM_INT 0

class Logger
{
private:
    BIO *bio_stdout;
public:
    Logger()
    {
        bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    }
    ~Logger()
    {
        BIO_free(bio_stdout);
    }
    int error(const char *from, const char *message)
    {
        printf("[Error] raised from [%s]: %s!\n", from, message);
        return 0;
    }
    int warning(const char *from, const char *message)
    {
        printf("[Warning] raised from [%s]: %s!\n", from, message);
        return 0;
    }

    int info(const char *message)
    {
        BIO_printf(bio_stdout, "[Info] %s.\n", message);
        return 0;
    }

    int parameter(const char *pName, BIGNUM *param)
    {
#ifdef LOG_PARAMS
        BIO_printf("[Parameter Log] ");
        BIO_printf("%s: %d\n", pName, BN_bn2dec(((BIGNUM *)param)));
#endif
        return 0;
    }

    int aes_printf(const char *format, ...)
    {
#ifdef LOG_AES
        va_list args;
        va_start(args, format);
        BIO_vprintf(bio_stdout, format, args);
        va_end(args);
#endif
        return 0;
    }

    int printf(const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        BIO_vprintf(bio_stdout, format, args);
        va_end(args);
        return 0;
    }
};

template <>
struct std::formatter<BIGNUM*> : std::formatter<std::string> {
  auto format(BIGNUM* p, format_context& ctx) const {
    char *str = BN_bn2hex(p);
    auto out = formatter<string>::format(std::format("{}", str), ctx);
    OPENSSL_free(str);
    return out;
  }
};

template <>
struct std::formatter<cECPoint> : std::formatter<std::string> {
  auto format(const cECPoint &point, format_context& ctx) const {
    auto out = formatter<string>::format(std::format("[{} {}]", point.x, point.y), ctx);
    return out;
  }
};



#endif
