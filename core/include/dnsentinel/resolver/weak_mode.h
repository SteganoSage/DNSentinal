#pragma once
/// @file resolver/weak_mode.h
/// Lab-only knobs that deliberately weaken the resolver's anti-spoofing, so
/// the Kaminsky poisoning attack (plan §5.10, experiment E5) can be run
/// against each rung of the defence ladder and measured.
///
/// This header only compiles in a build configured with
/// -DDNSENTINEL_WEAK_MODE=ON. A normal (release) build never defines the
/// macro, so none of this exists and no configuration can switch it on:
/// the resolver cannot be weakened except by rebuilding it on purpose.

#ifndef DNSENTINEL_WEAK_MODE
#error "weak_mode.h is lab-only; configure with -DDNSENTINEL_WEAK_MODE=ON (never a release build)"
#endif

#include <cstdint>

namespace dnsentinel::resolver {

/// The defence ladder is built by turning these on one at a time (the rest
/// of the ladder, 0x20 and spoof detection, uses the ordinary config knobs
/// `use_0x20` and `spoof_tcp_threshold`). `weaken` off == a normal build.
struct WeakMode {
    bool weaken = false;

    /// Entropy of the transaction ID, 1–16 bits. 16 is the real 16-bit ID;
    /// E5 part A shrinks it to 6–12 so the attack finishes quickly and the
    /// measured work can be checked against the model's mean of 2^bits.
    uint8_t txid_bits = 16;

    /// L0: hand out transaction IDs 0, 1, 2, ... instead of random ones, so
    /// an off-path attacker can predict the next one.
    bool sequential_txid = false;

    /// L0–L1: bind every upstream UDP query to this source port instead of a
    /// fresh random one, so the attacker doesn't have to guess it. 0 keeps
    /// the normal random ephemeral port.
    uint16_t fixed_source_port = 0;

    /// L0–L3: skip the bailiwick filter, so a server's answer is believed
    /// even when it carries records for zones it has no authority over
    /// (E5 part C, the malicious-authoritative case).
    bool accept_out_of_bailiwick = false;
};

}  // namespace dnsentinel::resolver
