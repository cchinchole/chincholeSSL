#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#ifndef LOGGER_HPP
#define LOGGER_HPP

#define PARAM_BN 0
#define PARAM_INT 0

class Logger{
    private:
        BIO *bio_stdout;
    public:
        Logger()
        {
            bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        }
        int error(const char* from, const char* message)
        {
            printf("[Error] raised from [%s]: %s!\n", from, message);
            return 0;
        }   
        int warning(const char* from, const char* message)
        {
            printf("[Warning] raised from [%s]: %s!\n", from, message);
            return 0;
        }

        int info(const char* message)
        {
            BIO_printf(bio_stdout, "[Info] %s.\n", message);
            return 0;
        }

        int parameter(const char *pName, BIGNUM* param)
        {
            #ifdef LOG_PARAMS
                BIO_printf("[Parameter Log] ");
                BIO_printf("%s: %d\n", pName, BN_bn2dec(((BIGNUM*)param)) );
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
#endif
extern Logger* _Logger;