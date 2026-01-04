#pragma once

#include <limits>
#include <stdexcept>
#include <cstddef>

namespace mshio {
namespace safe_math {

// Maximum reasonable size for memory allocation (1GB)
constexpr size_t MAX_REASONABLE_SIZE = 1024ULL * 1024ULL * 1024ULL;

// Check if multiplication would overflow
inline bool would_multiply_overflow(size_t a, size_t b) {
    if (a == 0 || b == 0) return false;
    return a > std::numeric_limits<size_t>::max() / b;
}

// Safe multiplication that throws on overflow
inline size_t safe_multiply(size_t a, size_t b, const char* context = "multiplication") {
    if (would_multiply_overflow(a, b)) {
        throw std::overflow_error(std::string("Integer overflow in ") + context);
    }
    size_t result = a * b;
    // Also check for unreasonably large allocations
    if (result > MAX_REASONABLE_SIZE) {
        throw std::length_error(std::string("Allocation size too large in ") + context);
    }
    return result;
}

// Check if a value is reasonable for use as array size
inline void validate_size(size_t size, const char* context = "size validation") {
    if (size > MAX_REASONABLE_SIZE) {
        throw std::length_error(std::string("Size too large in ") + context);
    }
}

// Safe cast from signed to unsigned, checking for negative values
template<typename T>
inline size_t safe_cast_to_size_t(T value, const char* context = "cast") {
    if (value < 0) {
        throw std::invalid_argument(std::string("Negative value in ") + context);
    }
    return static_cast<size_t>(value);
}

} // namespace safe_math
} // namespace mshio
