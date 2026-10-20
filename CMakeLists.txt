cmake_minimum_required(VERSION 3.20)
project(dnsentinel VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)  # std::expected
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Options ─────────────────────────────────────────────────────────────────
option(DNSENTINEL_ENABLE_DOT    "Enable DNS-over-TLS listener"    ON)
option(DNSENTINEL_ENABLE_DOH    "Enable DNS-over-HTTPS listener"  ON)
option(DNSENTINEL_ENABLE_ML     "Enable ML fast-path inference"   ON)
option(DNSENTINEL_ENABLE_TESTS  "Build unit and integration tests" ON)
option(DNSENTINEL_ENABLE_FUZZ   "Build fuzz targets"              OFF)
option(DNSENTINEL_SANITIZERS    "Enable ASan + UBSan"             OFF)
option(DNSENTINEL_WEAK_MODE     "Lab-only: allow deliberately weakened anti-spoofing (plan §5.10)" OFF)

# ─── Dependencies ────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
include(FetchContent)

# yaml-cpp reads config/dnsentinel.yaml. Fetched so no system package is needed.
set(YAML_CPP_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS   OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL       OFF CACHE BOOL "" FORCE)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)  # yaml-cpp 0.8.0 asks for 3.4, which CMake 4 refuses
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        0.8.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(yaml-cpp)

if(DNSENTINEL_ENABLE_TESTS)
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

# ─── Fuzzing instrumentation ─────────────────────────────────────────────────
# libFuzzer needs coverage feedback from the code under test, not just from
# the fuzz target, so everything below is instrumented (googletest above is not).
if(DNSENTINEL_ENABLE_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "DNSENTINEL_ENABLE_FUZZ needs clang: -DCMAKE_CXX_COMPILER=clang++")
    endif()
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
                        -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ─── Core library ────────────────────────────────────────────────────────────
# Uncomment each source as its module lands (build order: implementation plan §1).
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
    core/net/tls.cpp
    core/net/doh.cpp

    # Resolver
    core/resolver/recursive_resolver.cpp
    core/resolver/root_hints.cpp
    core/resolver/upstream.cpp
    core/resolver/server_selection.cpp
    # core/resolver/qname_minimisation.cpp

    # Cache
    core/cache/cache.cpp
    # negative caching (plan §4.2) lives in core/resolver/recursive_resolver.cpp
    # core/cache/serve_stale.cpp

    # Security
    # core/security/randomisation.cpp
    core/security/zero_x20.cpp
    core/security/bailiwick.cpp
    core/security/rrl.cpp

    # Policy
    core/policy/acl.cpp
    core/policy/blocklist_trie.cpp
    core/policy/blocklists.cpp
    core/policy/cname_check.cpp
    core/policy/rebinding.cpp
    core/policy/rate_limiter.cpp

    # Telemetry
    # core/telemetry/event_bus.cpp
    # core/telemetry/metrics.cpp
    # core/telemetry/query_log.cpp

    # Server: config loading, the query pipeline
    core/server/config.cpp
    core/server/query_processor.cpp
)

target_include_directories(dnsentinel_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)

target_link_libraries(dnsentinel_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
target_link_libraries(dnsentinel_core PRIVATE yaml-cpp::yaml-cpp)

# ─── DoT listener ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_DOT)
    # DoT is the TCP listener with TLS (core/net/tcp_listener.cpp, core/net/tls.cpp),
    # always built: OpenSSL is required anyway. This only defines the macro.
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_DOT=1)
endif()

# ─── DoH listener ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_DOH)
    # DoH is the TCP listener with HTTP framing; always built, like DoT.
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_DOH=1)
endif()

# ─── ML fast-path ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_ML)
    # The DGA classifier (README §7.8.2): the model ml/dga trains, read from models/dga.
    target_sources(dnsentinel_core PRIVATE
        core/ml/psl.cpp
        core/ml/dga_features.cpp
        core/ml/gbdt.cpp
        core/ml/dga_classifier.cpp
        core/ml/dga_check.cpp
    )
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_ML=1)
    # Experiment E9's inference timing (bench/dga_latency.cpp). Time it in a
    # Release build: cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
    add_executable(dga_latency bench/dga_latency.cpp)
    target_link_libraries(dga_latency PRIVATE dnsentinel_core)
endif()

# ─── Weak mode (lab-only, plan §5.10) ───────────────────────────────────────
# OFF by default: a release build literally cannot compile the weakening code,
# so no configuration can turn the resolver's anti-spoofing off.
if(DNSENTINEL_WEAK_MODE)
    target_compile_definitions(dnsentinel_core PUBLIC DNSENTINEL_WEAK_MODE=1)
    message(WARNING "DNSENTINEL_WEAK_MODE is ON: this build is for the attack lab only, never for real use.")
endif()

# ─── Main executable ────────────────────────────────────────────────────────
add_executable(dnsentinel core/main.cpp)
target_link_libraries(dnsentinel PRIVATE dnsentinel_core)

# ─── Tests ───────────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_TESTS)
    add_executable(dnsentinel_tests
        tests/unit/test_types.cpp
        tests/unit/wire/test_parser.cpp
        tests/unit/wire/test_builder.cpp
        tests/unit/wire/test_edns.cpp
        tests/unit/wire/test_name.cpp
        tests/unit/net/test_event_loop.cpp
        tests/unit/net/test_udp_listener.cpp
        tests/unit/net/test_tcp_listener.cpp
        tests/unit/net/test_tls.cpp
        tests/unit/net/test_doh.cpp
        tests/unit/cache/test_cache.cpp
        tests/unit/resolver/test_root_hints.cpp
        tests/unit/resolver/test_upstream.cpp
        tests/unit/resolver/test_recursive_resolver.cpp
        tests/unit/resolver/test_server_selection.cpp
        tests/unit/resolver/test_weak_mode.cpp  # compiles to nothing unless DNSENTINEL_WEAK_MODE=ON
        # negative caching is tested in tests/unit/resolver/test_recursive_resolver.cpp
        tests/unit/security/test_bailiwick.cpp
        tests/unit/server/test_config.cpp
        tests/unit/server/test_query_processor.cpp
        tests/unit/security/test_zero_x20.cpp
        tests/unit/policy/test_acl.cpp
        tests/unit/policy/test_blocklist_trie.cpp
        tests/unit/policy/test_blocklists.cpp
        tests/unit/policy/test_cname_check.cpp
        tests/unit/policy/test_rebinding.cpp
        tests/unit/policy/test_rate_limiter.cpp
        tests/unit/security/test_rrl.cpp
    )
    target_link_libraries(dnsentinel_tests PRIVATE
        dnsentinel_core
        GTest::gtest_main
    )
    target_compile_definitions(dnsentinel_tests PRIVATE
        DNSENTINEL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"  # tests read files in config/
    )
    include(GoogleTest)
    if(DNSENTINEL_ENABLE_ML)
        target_sources(dnsentinel_tests PRIVATE tests/unit/ml/test_dga_classifier.cpp tests/unit/ml/test_dga_check.cpp)
    endif()
    gtest_discover_tests(dnsentinel_tests)

    # The daemon end to end, offline, in a private network namespace.
    # Reported as skipped where unprivileged user namespaces are disabled.
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME offline_e2e
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/offline_e2e.py
                         $<TARGET_FILE:dnsentinel>)
        set_tests_properties(offline_e2e PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 60)
        # The DGA pipeline's Python tests; the ones that need scikit-learn or
        # LightGBM skip themselves where those aren't installed.
        add_test(NAME ml_python
                 COMMAND ${Python3_EXECUTABLE} -m unittest discover -s tests/ml -t .
                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(ml_python PROPERTIES TIMEOUT 300)
    endif()
endif()

# ─── Fuzz targets ────────────────────────────────────────────────────────────
if(DNSENTINEL_ENABLE_FUZZ)
    add_executable(fuzz_parser tests/fuzz/fuzz_parser.cpp)
    target_link_libraries(fuzz_parser PRIVATE dnsentinel_core)
    target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer)  # libFuzzer's main()
endif()
