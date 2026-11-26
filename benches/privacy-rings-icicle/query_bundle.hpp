// The XKQMSM01 format is defined by crates/groth16/examples/support/query_msm.rs.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <istream>
#include <limits>
#include <stdexcept>

namespace query_bundle {

using Field = std::array<std::uint8_t, 32>;
using G1 = std::array<Field, 2>;
using G2 = std::array<Field, 4>;

constexpr std::array<char, 8> magic = {'X', 'K', 'Q', 'M', 'S', 'M', '0', '1'};
constexpr std::size_t header_size = 12;
constexpr std::size_t record_size = 224;
constexpr std::size_t result_size = 192;

inline void read_exact(std::istream& input, char* destination, std::streamsize size) {
    if (!input.read(destination, size)) {
        throw std::runtime_error("truncated query bundle");
    }
}

inline std::uint32_t read_header(std::istream& input, std::uintmax_t length) {
    std::array<char, magic.size()> tag{};
    read_exact(input, tag.data(), tag.size());
    if (tag != magic) {
        throw std::runtime_error("invalid XKQMSM01 magic");
    }
    std::array<std::uint8_t, 4> count_bytes{};
    read_exact(input, reinterpret_cast<char*>(count_bytes.data()), count_bytes.size());
    std::uint32_t count = 0;
    for (std::size_t i = 0; i < count_bytes.size(); ++i) {
        count |= std::uint32_t{count_bytes[i]} << (8 * i);
    }
    if (count == 0 || count > std::numeric_limits<int>::max() ||
        length != header_size + result_size + std::uintmax_t{count} * record_size) {
        throw std::runtime_error("invalid query bundle count or length");
    }
    return count;
}

inline Field read_field(std::istream& input) {
    Field field{};
    read_exact(input, reinterpret_cast<char*>(field.data()), field.size());
    return field;
}

template <std::size_t Coordinates>
std::array<Field, Coordinates> read_point(std::istream& input) {
    std::array<Field, Coordinates> point{};
    for (Field& coordinate : point) {
        coordinate = read_field(input);
    }
    return point;
}

inline bool is_one(const Field& scalar) {
    Field one{};
    one.back() = 1;
    return scalar == one;
}

inline void require_end(std::istream& input) {
    if (input.peek() != std::char_traits<char>::eof() || input.bad()) {
        throw std::runtime_error("unexpected data after query bundle");
    }
}

}  // namespace query_bundle
