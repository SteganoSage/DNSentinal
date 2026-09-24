cmake_minimum_required(VERSION 3.20)
project(dnsentinel VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Options ─────────────────────────────────────────────────────────────────
option(DNSENTINEL_ENABLE_DOT    "Enable DNS-over-TLS listener"    ON)
option(DNSENTINEL_ENABLE_DOH    "Enable DNS-over-HTTPS listener"  ON)
option(DNSENTINEL_ENABLE_ML     "Enable ML fast-path inference"   ON)
option(DNSENTINEL_ENABLE_TESTS  "Build unit and integration tests" ON)
option(DNSENTINEL_ENABLE_FUZZ   "Build fuzz targets"              OFF)
option(DNSENTINEL_SANITIZERS    "Enable ASan + UBSan"             OFF)

# ─── Dependencies ────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(DNSENTINEL_ENABLE_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    FetchContent_MakeAvailable(googletest)
    enable_testing()
endif()

# ─── Sanitizers ──────────────────────────────────────────────────────────────
if(DNSENTINEL_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ─── Core library ────────────────────────────────────────────────────────────
add_library(dnsentinel_core STATIC
    # Wire format
    core/wire/parser.cpp
    core/wire/builder.cpp
    core/wire/name.cpp
    core/wire/edns.cpp

    # Networking
    core/net/event_loop.cpp
    core/net/udp_listener.cpp
    core/net/tcp_listener.cpp

    # Resolver
    core/resolver/recursive_resolver.cpp
    core/resolver/server_selection.cpp
    core/resolver/qname_minimisation.cpp

    # Cache
    core/cache/cache.cpp
    core/cache/negative_cache.cpp
    core/cache/serve_stale.cpp

    # Security
    core/security/randomisation.cpp
    core/security/zero_x20.cpp
    core/security/bailiwick.cpp
    core/security/rrl.cpp

    # Policy
    core/policy/acl.cpp
    core/policy/blocklist_trie.cpp
    core/policy/cname_check.cpp
    core/policy/rebinding.cpp
    core/policy/rate_limiter.cpp

    # Telemetry
    core/telemetry/event_bus.cpp
    core/telemetry/metrics.cpp
    core/telemetry/query_log.cpp
)

target_include_directories(dnsentinel_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)

target_link_libraries(dnsentinel_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# ─── DoT listener ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_DOT)
    target_sources(dnsentinel_core PRIVATE core/net/dot_listener.cpp)
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_DOT=1)
endif()

# ─── DoH listener ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_DOH)
    target_sources(dnsentinel_core PRIVATE core/net/doh_listener.cpp)
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_DOH=1)
endif()

# ─── ML fast-path ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_ML)
    target_sources(dnsentinel_core PRIVATE core/ml/dga_classifier.cpp)
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_ML=1)
endif()

# ─── Main executable ────────────────────────────────────────────────────────
add_executable(dnsentinel core/main.cpp)
target_link_libraries(dnsentinel PRIVATE dnsentinel_core)

# ─── Tests ───────────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_TESTS)
    add_executable(dnsentinel_tests
        tests/unit/wire/test_parser.cpp
        tests/unit/wire/test_builder.cpp
        tests/unit/wire/test_name.cpp
        tests/unit/cache/test_cache.cpp
        tests/unit/cache/test_negative_cache.cpp
        tests/unit/security/test_bailiwick.cpp
        tests/unit/security/test_zero_x20.cpp
        tests/unit/policy/test_blocklist_trie.cpp
        tests/unit/policy/test_rebinding.cpp
        tests/unit/ml/test_dga_classifier.cpp
    )
    target_link_libraries(dnsentinel_tests PRIVATE
        dnsentinel_core
        GTest::gtest_main
    )
    include(GoogleTest)
    gtest_discover_tests(dnsentinel_tests)
endif()

# ─── Fuzz targets ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_FUZZ)
    add_executable(fuzz_parser tests/fuzz/fuzz_parser.cpp)
    target_link_libraries(fuzz_parser PRIVATE dnsentinel_core)
    target_compile_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
