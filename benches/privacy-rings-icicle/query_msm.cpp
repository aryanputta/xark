#include "query_bundle.hpp"

#include <icicle/backend/msm_config.h>
#include <icicle/curves/params/bn254.h>
#include <icicle/msm.h>
#include <icicle/runtime.h>

#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using bn254::affine_t;
using bn254::g2_affine_t;
using bn254::g2_point_field_t;
using bn254::g2_projective_t;
using bn254::point_field_t;
using bn254::projective_t;
using bn254::scalar_t;

template <typename Field>
Field decode(const query_bundle::Field& bytes) {
    // The exchange format uses canonical big-endian bytes. ICICLE stores
    // canonical (non-Montgomery) field values in little-endian limb order.
    static_assert(Field::TLC * sizeof(std::uint32_t) == 32);
    Field value{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value.limbs_storage.limbs[i / 4] |=
            std::uint32_t{bytes[bytes.size() - 1 - i]} << (8 * (i % 4));
    }
    const auto modulus = Field::get_modulus();
    for (std::size_t i = Field::TLC; i > 0; --i) {
        const auto limb = value.limbs_storage.limbs[i - 1];
        if (limb < modulus.limbs[i - 1]) {
            return value;
        }
        if (limb > modulus.limbs[i - 1]) {
            break;
        }
    }
    throw std::runtime_error("noncanonical field in query bundle");
}

affine_t read_g1(std::istream& input) {
    const auto point = query_bundle::read_point<2>(input);
    const affine_t affine{decode<point_field_t>(point[0]), decode<point_field_t>(point[1])};
    if (!projective_t::from_affine(affine).is_on_curve()) {
        throw std::runtime_error("G1 point in query bundle is off-curve");
    }
    return affine;
}

g2_affine_t read_g2(std::istream& input) {
    const auto point = query_bundle::read_point<4>(input);
    // Exchange format: x.c1, x.c0, y.c1, y.c0. ICICLE: c0 then c1.
    const g2_affine_t affine{
        g2_point_field_t{decode<point_field_t>(point[1]), decode<point_field_t>(point[0])},
        g2_point_field_t{decode<point_field_t>(point[3]), decode<point_field_t>(point[2])},
    };
    if (!g2_projective_t::from_affine(affine).is_on_curve()) {
        throw std::runtime_error("G2 point in query bundle is off-curve");
    }
    return affine;
}

struct Inputs {
    std::vector<scalar_t> scalars;
    std::vector<affine_t> b1;
    std::vector<g2_affine_t> b2;
    affine_t expected_b1{};
    g2_affine_t expected_b2{};
};

Inputs load(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot open query bundle");
    }
    const auto count = query_bundle::read_header(file, std::filesystem::file_size(path));
    Inputs inputs;
    inputs.scalars.reserve(count);
    inputs.b1.reserve(count);
    inputs.b2.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto scalar = query_bundle::read_field(file);
        if (i == 0 && !query_bundle::is_one(scalar)) {
            throw std::runtime_error("query bundle lacks the constant-one scalar");
        }
        inputs.scalars.push_back(decode<scalar_t>(scalar));
        inputs.b1.push_back(read_g1(file));
        inputs.b2.push_back(read_g2(file));
    }
    inputs.expected_b1 = read_g1(file);
    inputs.expected_b2 = read_g2(file);
    query_bundle::require_end(file);
    return inputs;
}

void require_success(icicle::eIcicleError code, std::string_view operation) {
    if (code != icicle::eIcicleError::SUCCESS) {
        throw std::runtime_error(
            std::string(operation) + " failed, ICICLE status " + std::to_string(static_cast<int>(code))
        );
    }
}

int parse_arg(std::string_view text, int minimum) {
    int value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value < minimum) {
        throw std::runtime_error("invalid thread, sample or warmup count");
    }
    return value;
}

template <typename Projective, typename Affine>
std::vector<std::chrono::nanoseconds> measure(
    std::string_view query, const std::vector<scalar_t>& scalars,
    const std::vector<Affine>& points, const Affine& expected,
    const icicle::MSMConfig& config, int samples, int warmups
) {
    std::vector<std::chrono::nanoseconds> timings;
    timings.reserve(samples);
    for (int i = 0; i < warmups + samples; ++i) {
        Projective output{};
        const auto start = std::chrono::steady_clock::now();
        const auto status = icicle::msm(
            scalars.data(), points.data(), static_cast<int>(scalars.size()), config, &output
        );
        const auto stop = std::chrono::steady_clock::now();
        require_success(status, query);
        // Group equality is checked outside timing, including on warmups.
        if (!output.is_on_curve() ||
            (expected.is_zero() ? !output.is_zero() : output.is_zero() || output.to_affine() != expected)) {
            throw std::runtime_error(std::string(query) + " disagrees with the Arkworks result");
        }
        if (i >= warmups) {
            timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start));
        }
    }
    return timings;
}

void print(std::string_view query, const std::vector<std::chrono::nanoseconds>& timings) {
    for (std::size_t i = 0; i < timings.size(); ++i) {
        std::cout << "query msm icicle: query=" << query << " sample=" << i + 1
                  << " icicle_ns=" << timings[i].count() << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3 || argc > 5) {
            throw std::runtime_error(
                "usage: icicle-query-msm <XKQMSM01 bundle> <thread-cap> [samples [warmups]]"
            );
        }
        const int threads = parse_arg(argv[2], 1);
        const int samples = argc >= 4 ? parse_arg(argv[3], 1) : 30;
        const int warmups = argc == 5 ? parse_arg(argv[4], 0) : 3;
        if (samples > std::numeric_limits<int>::max() - warmups) {
            throw std::runtime_error("sample and warmup count overflow");
        }
        const auto inputs = load(argv[1]);
        require_success(icicle_set_device(icicle::Device("CPU", 0)), "select CPU:0");
        icicle::ConfigExtension extension;
        extension.set<int>(CpuBackendConfig::CPU_NOF_THREADS, threads);
        auto config = icicle::default_msm_config();
        config.ext = &extension;

        const auto b1 = measure<projective_t>("b1", inputs.scalars, inputs.b1, inputs.expected_b1, config, samples, warmups);
        const auto b2 = measure<g2_projective_t>("b2", inputs.scalars, inputs.b2, inputs.expected_b2, config, samples, warmups);
        std::cout << "query msm icicle verified: terms=" << inputs.scalars.size()
                  << " thread_cap=" << threads << " samples=" << samples
                  << " warmups=" << warmups
                  << " backend=CPU:0 precompute_factor=1 batch_size=1 canonical_host=1 async=0"
                  << " bundle=XKQMSM01 reference=arkworks"
                  << " icicle_commit=6c77775961b0e4dc2be359feec1ac11536c18043\n";
        print("b1", b1);
        print("b2", b2);
    } catch (const std::exception& error) {
        std::cerr << "icicle-query-msm: " << error.what() << '\n';
        return 1;
    }
}
