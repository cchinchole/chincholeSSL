#pragma once
#include "../utils/bytes.hpp"
#include "../types.hpp"
#include <memory>
#include <string>
#include <utility>


namespace cssl
{
class EcSignature
{
    friend class Ec;

public:
    static EcSignature from(const std::string &hexR, const std::string &hexS);
    EcSignature(const EcSignature &) = delete;
    EcSignature(EcSignature &&) = default;
    EcSignature &operator=(const EcSignature &) = delete;
    EcSignature &operator=(EcSignature &&) = default;
    ~EcSignature();
    EcSignature();
    std::pair<std::string, std::string> get_rs();

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

class Ec
{
public:
    static Ec generate_key(EC_GROUP group);
    static Ec from(EC_GROUP group, const std::string &hexPriv,
                          const std::string &hexPubX,
                          const std::string &hexPubY);

    EcSignature sign(ByteSpan message,
                     DIGEST_MODE shaMode = DIGEST_MODE::SHA_512) const;
    bool verify(const EcSignature &sig, ByteSpan message,
                DIGEST_MODE shaMode = DIGEST_MODE::SHA_512) const;

    Ec(const Ec &) = delete;
    Ec &operator=(const Ec &) = delete;
    Ec(Ec &&) noexcept;
    Ec &operator=(Ec &&) noexcept;
    ~Ec();
    Ec(EC_GROUP group);

private:
    struct Impl;
    std::unique_ptr<Impl> m_pImpl;
};
}
