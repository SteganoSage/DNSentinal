#pragma once
/// @file ml/dga_config.h
/// The ml.dga config section: plain settings, so the config loader builds
/// with or without the ML code (DNSENTINEL_ENABLE_ML).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

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
    /// Public suffixes whose next label the provider assigns, random by design
    /// (CloudFront's d1bxh8uas1mnw7.cloudfront.net): names under them are never
    /// scored. In the Public Suffix List's private section each such name is its
    /// own registrable domain. The classifier keeps that section so that generated
    /// names under dynamic DNS (x7k2.ddns.net), which whoever registers them
    /// chooses, are still scored. On real browsing (the tunnel dataset's 39.7 h),
    /// 533 of the 534 domains flagged were under these three.
    std::vector<std::string> provider_suffixes = {"cloudfront.net", "cloudapp.net", "global.ssl.fastly.net"};
    double      threshold  = 0;       // flag scores above this; 0: the model's own (0.1% FPR in training)
    size_t      cache_size = 100000;  // verdicts kept, one per registrable domain; 0: no cache
};

}  // namespace dnsentinel::ml
