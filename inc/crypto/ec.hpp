#pragma once
#include "../hash/hash.hpp"
#include "../utils/bytes.hpp"
#include <span>
#include <string>
#include <utility>

enum class ECGroup
{
    P224,
    P256,
    P384,
    P521,
    NONE
};

namespace cSSL
{
class ECSignature
{
    friend class ECKeyPair;

public:
    static ECSignature From(const std::string &hexR, const std::string &hexS);

    ECSignature(const ECSignature &) = default;
    ECSignature(ECSignature &&) = default;
    ECSignature &operator=(const ECSignature &) = default;
    ECSignature &operator=(ECSignature &&) = default;
    ~ECSignature();
    ECSignature();
    std::pair<std::string, std::string> getPairRS();

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

class ECKeyPair
{
public:
    static ECKeyPair Generate(ECGroup group);
    static ECKeyPair From(ECGroup group, const std::string &hexPriv,
                          const std::string &hexPubX,
                          const std::string &hexPubY);

    ECSignature sign(std::span<const uint8_t> message,
                     DIGEST_MODE shaMode = DIGEST_MODE::SHA_512) const;
    bool verify(const ECSignature &sig, std::span<const uint8_t> message,
                DIGEST_MODE shaMode = DIGEST_MODE::SHA_512) const;

    ECKeyPair(const ECKeyPair &) = delete;
    ECKeyPair &operator=(const ECKeyPair &) = delete;
    ECKeyPair(ECKeyPair &&) noexcept;
    ECKeyPair &operator=(ECKeyPair &&) noexcept;
    ~ECKeyPair();
    ECKeyPair(ECGroup group);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};
}
