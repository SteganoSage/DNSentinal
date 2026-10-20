/// @file bench/dga_latency.cpp
/// Experiment E9, the inference half: how long the DGA classifier takes per
/// name, in the resolver's own C++ (EVALUATION.md E9: <= 50 µs median per
/// first-seen domain). Times every stage separately, on each name:
///
///   split      the Public Suffix List split (registrable label + suffix)
///   features   the 20 features, given the split
///   trees      the 450 trees and the sigmoid, given the features
///   classify   all three, from the name
///   cold       DgaCheck::check on a name seen for the first time: what a
///              query pays when its registrable domain is new (classify, plus
///              the special-use check and the verdict cache)
///   warm       DgaCheck::check on a name already judged: a cache hit
///
/// Each stage is timed in a loop of its own over every name, --repeat times
/// (the verdict cache cleared each round, so "cold" stays cold), and each
/// name keeps its median; the summary gives the median, p90, p99 and
/// maximum over names. Build optimised (-DCMAKE_BUILD_TYPE=Release):
/// the tool says so loudly when it isn't.
///
///   build/release/dga_latency                       # the parity names (tests/unit/ml)
///   build/release/dga_latency --names ml/data/dga_dataset.csv --limit 20000
///
/// Writes <out>/dga_latency.csv (per name) and <out>/dga_latency.json (summary).

#include "dnsentinel/ml/dga_check.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::ml;
using Clock = std::chrono::steady_clock;

namespace {

struct Options {
    std::string model  = "models/dga";
    std::string words  = "config/english_words.txt";
    std::string names  = "tests/unit/ml/dga_parity.tsv";
    std::string out    = "bench/results/e9";
    size_t      limit  = 0;  // 0: every name
    int         repeat = 7;
};

constexpr bool kOptimised =
#ifdef __OPTIMIZE__
    true;
#else
    false;
#endif

double micros(Clock::duration d) { return std::chrono::duration<double, std::micro>(d).count(); }

double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return n == 0 ? 0 : n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

double percentile(std::vector<double> v, double p) {  // nearest rank
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    const size_t rank = static_cast<size_t>(std::ceil(p / 100.0 * static_cast<double>(v.size())));
    return v[std::clamp<size_t>(rank, 1, v.size()) - 1];
}

/// Names from a file: the first tab- or comma-separated field of each line,
/// skipping comments and a "domain" header.
std::vector<std::string> read_names(const std::string& path, size_t limit) {
    std::ifstream            in(path);
    std::vector<std::string> names;
    std::string              line;
    while (std::getline(in, line)) {
        if (line.empty() || line.front() == '#') continue;
        const std::string name = line.substr(0, line.find_first_of("\t,"));
        if (name.empty() || name == "domain") continue;
        names.push_back(name);
    }
    if (limit && names.size() > limit) {  // an even sample, the same every run
        std::mt19937 rng(9);
        std::shuffle(names.begin(), names.end(), rng);
        names.resize(limit);
    }
    return names;
}

std::string cpu_model() {
    std::ifstream in("/proc/cpuinfo");
    std::string   line;
    while (std::getline(in, line)) {
        if (line.starts_with("model name")) return line.substr(line.find(':') + 2);
    }
    return "unknown";
}

void usage() {
    std::cerr << "usage: dga_latency [--model DIR] [--words FILE] [--names FILE] [--limit N] [--repeat N] [--out DIR]\n";
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (i + 1 >= argc) {
            usage();
            return 2;
        }
        const std::string value = argv[++i];
        if (arg == "--model") o.model = value;
        else if (arg == "--words") o.words = value;
        else if (arg == "--names") o.names = value;
        else if (arg == "--out") o.out = value;
        else if (arg == "--limit") o.limit = std::stoul(value);
        else if (arg == "--repeat") o.repeat = std::max(1, std::stoi(value));
        else {
            usage();
            return 2;
        }
    }
    if (!kOptimised) {
        std::cerr << "WARNING: built without optimisation: these times say nothing about the resolver.\n"
                     "         cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release\n";
    }

    const auto started = Clock::now();
    auto       loaded  = DgaClassifier::load(o.model, o.words);
    if (!loaded) {
        std::cerr << loaded.error() << "\n";
        return 1;
    }
    const double         load_ms = micros(Clock::now() - started) / 1000;
    const DgaClassifier& model   = *loaded;

    std::vector<std::string> texts;
    std::vector<Name>        names;
    StringSet                domains;  // one name per registrable domain: "first-seen" must be
    for (const auto& text : read_names(o.names, o.limit)) {
        auto name = Name::from_string(text);
        // What DgaCheck would skip (special-use, single label, not a host name) isn't inference.
        const auto split = model.split(text);
        if (!name || name->labels.size() < 2 || DgaCheck::special_use(name->labels.back()) || !split ||
            !domains.insert(split->registrable()).second) {
            continue;
        }
        texts.push_back(text);
        names.push_back(std::move(*name));
    }
    if (names.empty()) {
        std::cerr << o.names << ": no names to time\n";
        return 1;
    }

    const size_t n = names.size();
    std::vector<SplitName>           splits;
    std::vector<std::vector<double>> inputs;
    for (const auto& text : texts) {
        splits.push_back(*model.split(text));
        inputs.push_back(model.inputs(splits.back()));
    }

    // Each stage in a loop of its own over every name, so each is timed with
    // its own data in the cache, as when names arrive one after another.
    // Round -1 warms caches and clocks up, unrecorded; each name keeps its
    // median over the rounds.
    double sink = 0;  // keeps the optimiser from dropping the work
    auto   time = [&](auto&& work) {
        std::vector<std::vector<double>> rounds(static_cast<size_t>(o.repeat), std::vector<double>(n));
        for (int round = -1; round < o.repeat; ++round) {
            for (size_t i = 0; i < n; ++i) {
                const auto t0 = Clock::now();
                sink += work(i);
                const auto t1 = Clock::now();
                if (round >= 0) rounds[static_cast<size_t>(round)][i] = micros(t1 - t0);
            }
        }
        std::vector<double> per_name(n);
        for (size_t i = 0; i < n; ++i) {
            std::vector<double> times;
            for (const auto& round : rounds) times.push_back(round[i]);
            per_name[i] = median(times);
        }
        return per_name;
    };
    const auto split    = time([&](size_t i) { return static_cast<double>(model.split(texts[i])->label.size()); });
    const auto features = time([&](size_t i) { return model.inputs(splits[i])[0]; });
    const auto trees    = time([&](size_t i) { return model.trees().predict(inputs[i]); });
    const auto classify = time([&](size_t i) { return model.classify(texts[i])->score; });

    // The resolver's own path (DgaCheck::check): first-seen names, then the
    // same names again from the verdict cache.
    DgaConfig config;
    config.cache_size = n + 1;
    DgaCheck            check(model, StringSet{}, config);
    std::vector<std::vector<double>> cold_rounds(static_cast<size_t>(o.repeat), std::vector<double>(n));
    std::vector<std::vector<double>> warm_rounds = cold_rounds;
    for (int round = -1; round < o.repeat; ++round) {
        check.clear();  // every name is new again
        for (size_t pass = 0; pass < 2; ++pass) {
            for (size_t i = 0; i < n; ++i) {
                const auto t0     = Clock::now();
                const auto result = check.check(names[i]);
                const auto t1     = Clock::now();
                sink += result ? result->verdict.score : 0;
                if (round >= 0) (pass ? warm_rounds : cold_rounds)[static_cast<size_t>(round)][i] = micros(t1 - t0);
            }
        }
    }
    auto medians = [&](const std::vector<std::vector<double>>& rounds) {
        std::vector<double> out(n);
        for (size_t i = 0; i < n; ++i) {
            std::vector<double> times;
            for (const auto& round : rounds) times.push_back(round[i]);
            out[i] = median(times);
        }
        return out;
    };
    const auto cold = medians(cold_rounds), warm = medians(warm_rounds);

    std::filesystem::create_directories(o.out);
    std::ofstream csv(o.out + "/dga_latency.csv");
    csv << "name,label_length,split_us,features_us,trees_us,classify_us,cold_us,warm_us,score,dga\n";
    for (size_t i = 0; i < n; ++i) {
        const auto verdict = model.classify(texts[i]);
        const auto parts   = model.split(texts[i]);
        csv << texts[i] << "," << parts->label.size() << "," << split[i] << "," << features[i] << "," << trees[i]
            << "," << classify[i] << "," << cold[i] << "," << warm[i] << "," << verdict->score << ","
            << (verdict->dga ? 1 : 0) << "\n";
    }

    const std::vector<std::pair<std::string, const std::vector<double>*>> stages = {
        {"split", &split}, {"features", &features}, {"trees", &trees}, {"classify", &classify},
        {"cold", &cold},   {"warm", &warm}};
    std::ostringstream json;
    json << "{\n \"names\": " << n << ",\n \"repeat\": " << o.repeat << ",\n \"optimised\": "
         << (kOptimised ? "true" : "false") << ",\n \"cpu\": \"" << cpu_model() << "\",\n \"compiler\": \"" << __VERSION__
         << "\",\n \"model\": {\"trees\": " << model.trees().tree_count() << ", \"nodes\": " << model.trees().node_count()
         << ", \"features\": " << model.features().size() << ", \"load_ms\": " << load_ms << "},\n \"stages_us\": {";
    std::printf("%zu names, median of %d rounds each (%s build, %s)\n", n, o.repeat,
                kOptimised ? "optimised" : "UNOPTIMISED", cpu_model().c_str());
    std::printf("model: %zu trees, %zu nodes, %zu features; loaded in %.0f ms\n\n", model.trees().tree_count(),
                model.trees().node_count(), model.features().size(), load_ms);
    std::printf("%-10s %9s %9s %9s %9s   (µs per name)\n", "stage", "median", "p90", "p99", "max");
    for (size_t s = 0; s < stages.size(); ++s) {
        const auto& [stage, v] = stages[s];
        const double med = median(*v), p90 = percentile(*v, 90), p99 = percentile(*v, 99),
                     max = *std::max_element(v->begin(), v->end());
        std::printf("%-10s %9.2f %9.2f %9.2f %9.2f\n", stage.c_str(), med, p90, p99, max);
        json << (s ? ", " : "") << "\n  \"" << stage << "\": {\"median\": " << med << ", \"p90\": " << p90
             << ", \"p99\": " << p99 << ", \"max\": " << max << "}";
    }
    const double cold_median = median(cold);
    const bool   met         = cold_median <= 50.0;
    json << "\n },\n \"target_us\": 50,\n \"target_met\": " << (met ? "true" : "false") << "\n}\n";
    std::ofstream(o.out + "/dga_latency.json") << json.str();
    std::printf("\nE9 target, <= 50 µs median per first-seen domain: %.2f µs, %s\n", cold_median,
                met ? "met" : "NOT met");
    std::printf("wrote %s/dga_latency.csv and dga_latency.json\n", o.out.c_str());
    return sink == -1 ? 1 : 0;  // never true; uses the sink
}
