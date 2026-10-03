#pragma once
/// @file policy/acl.h
/// Access control (plan §5.5): only clients on configured subnets get
/// answers. An open resolver, one that answers anyone, is the main tool of
/// DNS amplification attacks (README §7.6.1, requirement R5).

#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dnsentinel::policy {

/// A client's IP address. An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is
/// turned back into the IPv4 address it is, so both forms of one client
/// count as one (for access control, and per-client and per-network limits).
struct IpAddress {
    sa_family_t             family = AF_UNSPEC;
    std::array<uint8_t, 16> bytes{};  // IPv4 uses the first 4

    /// The address of its network: every bit past the first `prefix` cleared.
    [[nodiscard]] IpAddress network(uint8_t prefix) const;

    /// e.g. "192.168.1.5" or "fd00::1".
    [[nodiscard]] std::string to_string() const;

    bool operator==(const IpAddress&) const = default;
};

struct IpAddressHash {
    size_t operator()(const IpAddress& a) const noexcept;
};

/// `client`'s IP address, or nullopt if it isn't an IPv4 or IPv6 address.
[[nodiscard]] std::optional<IpAddress> ip_address(const sockaddr_storage& client);

/// An IPv4 or IPv6 network in CIDR form.
struct Subnet {
    sa_family_t             family = AF_INET;
    std::array<uint8_t, 16> network{};  // IPv4 uses the first 4 bytes
    uint8_t                 prefix = 0;

    /// True if `client`'s address is inside this network. An IPv4-mapped
    /// IPv6 address (::ffff:a.b.c.d) is matched as the IPv4 address it is.
    [[nodiscard]] bool contains(const sockaddr_storage& client) const;

    /// CIDR text, e.g. "192.168.0.0/16".
    [[nodiscard]] std::string to_string() const;

    bool operator==(const Subnet&) const = default;
};

/// Parse "a.b.c.d/n", "x:y::/n", or a bare address (a single host: /32 or
/// /128). Bits set past the prefix are an error, with a suggestion,
/// because "10.1.2.0/8" is almost always a typo.
[[nodiscard]] std::expected<Subnet, std::string> parse_subnet(std::string_view text);

enum class DenyAction {
    Refuse,  // answer REFUSED: polite, and no bigger than the query
    Drop,    // send nothing at all
};

struct AccessConfig {
    std::vector<Subnet> allow = localhost();
    DenyAction          deny  = DenyAction::Refuse;

    /// The default when nothing is configured: this machine only.
    static std::vector<Subnet> localhost();
};

class AccessControl {
public:
    explicit AccessControl(AccessConfig config) : config_(std::move(config)) {}

    /// True if `client` is on one of the allowed subnets.
    [[nodiscard]] bool allows(const sockaddr_storage& client) const;

    [[nodiscard]] DenyAction deny_action() const { return config_.deny; }
    [[nodiscard]] const std::vector<Subnet>& allowed() const { return config_.allow; }

private:
    AccessConfig config_;
};

}  // namespace dnsentinel::policy
