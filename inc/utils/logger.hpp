#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "../crypto/ec.hpp"
#include "../utils/bytes.hpp"
#include <format>
#include <openssl/bn.h>
#include <sstream>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <memory>
#include <mutex>
#include <chrono>
#include <iostream>

class LoggerClass {
public:
    template <typename... Args>
    void print(const std::format_string<Args...> fmt, Args&&... args) {
#if DEBUG
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << std::format(fmt, std::forward<Args>(args)...) << '\n';
#endif
    }
    
    template <typename... Args>
    void printAlways(const std::format_string<Args...> fmt, Args&&... args) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << std::format(fmt, std::forward<Args>(args)...) << '\n';
    }

private:
    std::mutex mutex_;
};
inline std::shared_ptr<LoggerClass> Logger = std::make_shared<LoggerClass>();

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
struct std::formatter<ByteArray> : std::formatter<std::string> {
  auto format(const ByteArray &array, format_context& ctx) const {
    auto out = formatter<string>::format(std::format("{}", bytesToHex(array)), ctx);
    return out;
  }
};

template <>
struct std::formatter<bool> : std::formatter<std::string> {
  auto format(const bool boolean, format_context& ctx) const {
    auto out = formatter<string>::format(std::format("{}", boolean == 1 ? "True" : "False"), ctx);
    return out;
  }
};

inline std::string getCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::tm local_tm;
    localtime_r(&t, &local_tm);

    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%H:%M:%S");
    return oss.str();
}

// Formatter specialization for uint8_t[4][4]
template<>
struct std::formatter<uint8_t[4][4]> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }

    template<typename FormatContext>
    auto format(const uint8_t (&state)[4][4], FormatContext& ctx) const {
        auto out = ctx.out();
        out = std::format_to(out, "[\n");
        for (int i = 0; i < 4; ++i) {
            out = std::format_to(out, "  [");
            for (int j = 0; j < 4; ++j) {
                out = std::format_to(out, "{:2d}", state[i][j]);
                if (j < 3) out = std::format_to(out, ", ");
            }
            out = std::format_to(out, "]");
            if (i < 3) out = std::format_to(out, ",");
            out = std::format_to(out, "\n");
        }
        return std::format_to(out, "]");
    }
};

//This will always print, only the named ones such as AES, RSA, EC, etc. will print only if debug mode is enabled.
#define PRINT(fmt, ...) Logger->printAlways("[{}] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define PRINT_SUCCESS(fmt, ...) Logger->printAlways("[{}] [ \e[32mSUCCEEDED\e[0m ] " fmt, getCurrentTime(), ##__VA_ARGS__);
#define PRINT_TEST_PASS(fmt, ...) Logger->printAlways("[{}] [ \e[32mTEST SUCCEEDED\e[0m ] " fmt, getCurrentTime(), ##__VA_ARGS__);
#define PRINT_TEST_FAILED(fmt, ...) Logger->printAlways("[{}] [ \e[31mTEST FAILED\e[0m ] " fmt, getCurrentTime(), ##__VA_ARGS__);

//Following below only print if the DEBUG flag is passed
#define LOG_INFO(fmt, ...) Logger->print("[{}] [ INFO ] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define LOG_AES(fmt, ...) Logger->print("[{}] [ AES ] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define LOG_RSA(fmt, ...) Logger->print("[{}] [ RSA ] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define LOG_EC(fmt, ...) Logger->print("[{}] [ EC ] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define LOG_HASH(fmt, ...) Logger->print("[{}] [ HASH ] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) Logger->print("[{}] [ \e[33mWARNING\e[0m ] " fmt, getCurrentTime(), ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) Logger->print("[{}] [ \e[31mERROR\e[0m ] " fmt, getCurrentTime(), ## __VA_ARGS__)

#endif
