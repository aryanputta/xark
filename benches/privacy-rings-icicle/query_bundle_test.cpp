#include "query_bundle.hpp"

#include <iostream>
#include <sstream>
#include <string>

namespace {

void require(bool condition) {
    if (!condition) {
        throw std::runtime_error("query bundle regression");
    }
}

template <typename Check>
void require_failure(Check check) {
    try {
        check();
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error("invalid query bundle was accepted");
}

std::string fixture() {
    std::string bytes(query_bundle::magic.begin(), query_bundle::magic.end());
    bytes.append("\x01\x00\x00\x00", 4);
    bytes.append(query_bundle::record_size + query_bundle::result_size, '\0');
    bytes[query_bundle::header_size + 31] = 1;
    bytes[query_bundle::header_size + 32] = 2;
    bytes[query_bundle::header_size + 96] = 3;
    bytes[query_bundle::header_size + query_bundle::record_size] = 4;
    bytes[query_bundle::header_size + query_bundle::record_size + 64] = 5;
    return bytes;
}

void check_layout() {
    const auto bytes = fixture();
    std::istringstream input(bytes);
    require(query_bundle::read_header(input, bytes.size()) == 1);
    require(query_bundle::is_one(query_bundle::read_field(input)));
    require(query_bundle::read_point<2>(input)[0][0] == 2);
    require(query_bundle::read_point<4>(input)[0][0] == 3);
    require(query_bundle::read_point<2>(input)[0][0] == 4);
    require(query_bundle::read_point<4>(input)[0][0] == 5);
    query_bundle::require_end(input);
    require(!query_bundle::is_one(query_bundle::Field{}));
}

void check_invalid_headers() {
    auto bytes = fixture();
    bytes[0] = 'Y';
    require_failure([&] {
        std::istringstream input(bytes);
        query_bundle::read_header(input, bytes.size());
    });
    for (const char count : {char{0}, char{2}}) {
        bytes = fixture();
        bytes[8] = count;
        require_failure([&] {
            std::istringstream input(bytes);
            query_bundle::read_header(input, bytes.size());
        });
    }
    bytes = fixture();
    bytes[11] = static_cast<char>(0x80);
    require_failure([&] {
        std::istringstream input(bytes);
        query_bundle::read_header(input, bytes.size());
    });
    bytes = fixture();
    for (std::size_t length : {std::size_t{11}, bytes.size() - 1, bytes.size() + 1}) {
        const auto invalid = bytes.substr(0, length) + (length > bytes.size() ? "X" : "");
        require_failure([&] {
            std::istringstream input(invalid);
            query_bundle::read_header(input, invalid.size());
        });
    }
}

void check_inconsistent_file_reads() {
    const auto bytes = fixture();
    require_failure([&] {
        std::istringstream input(bytes.substr(0, query_bundle::header_size + 31));
        query_bundle::read_header(input, bytes.size());
        query_bundle::read_field(input);
    });
    require_failure([&] {
        std::istringstream input("X");
        query_bundle::require_end(input);
    });
}

}  // namespace

int main() {
    check_layout();
    check_invalid_headers();
    check_inconsistent_file_reads();
    std::cout << "XKQMSM01 framing tests passed\n";
}
