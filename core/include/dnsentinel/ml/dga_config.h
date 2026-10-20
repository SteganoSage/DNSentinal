#pragma once
/// @file ml/dga_config.h
/// The ml.dga config section: plain settings, so the config loader builds
/// with or without the ML code (DNSENTINEL_ENABLE_ML).

#include <cstddef>
#include <cstdint>
#include <string>

namespace dnsentinel::ml {

enum class DgaMode : uint8_t {
    Monitor,  // log what the classifier flags, answer as usual
    Enforce,  // answer flagged names like blocked ones (policy.block_response)
};

struct DgaConfig {
    bool        enabled = false;
    DgaMode     mode    = DgaMode::Monitor;
    std::string model   = "models/dga";                // dga_lgbm.txt, features.txt, public_suffixes.txt
    std::string words   = "config/english_words.txt";  // the word list the model was trained with
    /// Popular sites, never scored (README §7.8.2: the Tranco top 100k the
    /// model's benign training names were kept apart from). "Rank,domain"
    /// or one domain per line. Empty: every name is scored.
    std::string allowlist;
    double      threshold  = 0;       // flag scores above this; 0: the model's own (0.1% FPR in training)
    size_t      cache_size = 100000;  // verdicts kept, one per registrable domain; 0: no cache
};

}  // namespace dnsentinel::ml
