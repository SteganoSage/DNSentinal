/// @file security/bailiwick.cpp
/// Out-of-bailiwick record filtering.

#include "dnsentinel/security/bailiwick.h"

#include <vector>

namespace dnsentinel::security {

size_t filter_to_bailiwick(Message& response, const Name& zone) {
    size_t removed = 0;
    for (std::vector<RR>* section : {&response.answers, &response.authority, &response.additional}) {
        removed += std::erase_if(*section, [&](const RR& rr) { return !rr.name.is_subdomain_of(zone); });
    }
    return removed;
}

}  // namespace dnsentinel::security
