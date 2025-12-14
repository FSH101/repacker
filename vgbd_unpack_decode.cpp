// vgbd_unpack_decode.cpp
// C++17: Decrypt (XOR) + unpack VGBD .img containers that hold Zstandard frames.
//
// Mirrors the Python script behavior:
// - Auto-detect: if input already starts with "VGBD", skip decrypt.
// - Otherwise: skip first 4 bytes, decrypt the rest:
//      out[i] = enc_body[i] XOR (255 - (i % 255))
// - Parse VGBD:
//      u32 count at 0x18 (LE)
//      u32 names_offset at 0x20 (LE)
//      names table at names_offset: [u32 len][ascii bytes] * count
// - Find Zstd frames by magic 0x28B52FFD before names_offset.
// - For each frame (bounded by next frame start or names_offset), decompress and write to output.
//
// Build (example with vcpkg):
//   vcpkg install zstd
//   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
//   cmake --build build --config Release
//
// Or link against your own zstd build.
//
// Usage:
//   vgbd_unpack_decode.exe <input.img> -o out_dir [--list] [--decoded-out decoded.img] [--keep-paths]
//
// Notes:
// - Requires zstd headers/libs: https://github.com/facebook/zstd
//

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>

#include <zstd.h>

namespace fs = std::filesystem;

static constexpr uint8_t VGBD_MAGIC[4] = {'V','G','B','D'};
static constexpr uint8_t ZSTD_MAGIC[4] = {0x28, 0xB5, 0x2F, 0xFD};

static uint32_t read_u32_le(const std::vector<uint8_t>& buf, size_t off) {
    if (off + 4 > buf.size()) throw std::runtime_error("read_u32_le: out of range");
    return (uint32_t(buf[off + 0])      ) |
           (uint32_t(buf[off + 1]) <<  8) |
           (uint32_t(buf[off + 2]) << 16) |
           (uint32_t(buf[off + 3]) << 24);
}

static std::vector<uint8_t> read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to open input file: " + p.string());
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) throw std::runtime_error("Failed to get file size: " + p.string());
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> data((size_t)sz);
    if (sz > 0) f.read(reinterpret_cast<char*>(data.data()), sz);
    if (!f && sz > 0) throw std::runtime_error("Failed to read file: " + p.string());
    return data;
}

static void write_file(const fs::path& p, const std::vector<uint8_t>& data) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to write file: " + p.string());
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
    if (!f) throw std::runtime_error("Failed while writing file: " + p.string());
}

static bool starts_with_magic(const std::vector<uint8_t>& buf, const uint8_t magic[4]) {
    return buf.size() >= 4 && std::memcmp(buf.data(), magic, 4) == 0;
}

static std::vector<uint8_t> decrypt_payload(const std::vector<uint8_t>& raw) {
    // Decrypt according to decoder.txt:
    // - first 4 bytes are header (ignored)
    // - remaining bytes: out[i] = enc_body[i] XOR (255 - (i % 255))
    if (raw.size() < 4) throw std::runtime_error("Encrypted file too short (<4 bytes).");
    const size_t body_len = raw.size() - 4;
    std::vector<uint8_t> out(body_len);
    for (size_t i = 0; i < body_len; ++i) {
        uint8_t b = raw[4 + i];
        uint8_t key = (uint8_t)(255 - (i % 255));
        out[i] = (uint8_t)(b ^ key);
    }
    return out;
}

static std::vector<std::string> parse_names(const std::vector<uint8_t>& buf, uint32_t names_offset, uint32_t count) {
    std::vector<std::string> names;
    names.reserve(count);

    size_t p = (size_t)names_offset;
    for (uint32_t i = 0; i < count; ++i) {
        if (p + 4 > buf.size()) throw std::runtime_error("Names table truncated (len).");
        uint32_t ln = read_u32_le(buf, p);
        p += 4;
        if (p + ln > buf.size()) throw std::runtime_error("Names table truncated (name bytes).");
        std::string name;
        name.assign(reinterpret_cast<const char*>(buf.data() + p), reinterpret_cast<const char*>(buf.data() + p + ln));
        p += ln;
        // Keep ASCII-ish; if bytes are non-ascii they will still be preserved in string.
        names.push_back(name);
    }
    return names;
}

static std::vector<size_t> find_frames(const std::vector<uint8_t>& buf, size_t end_off) {
    std::vector<size_t> idxs;
    if (end_off > buf.size()) end_off = buf.size();

    for (size_t i = 0; i + 4 <= end_off; ++i) {
        if (buf[i] == ZSTD_MAGIC[0] && buf[i+1] == ZSTD_MAGIC[1] && buf[i+2] == ZSTD_MAGIC[2] && buf[i+3] == ZSTD_MAGIC[3]) {
            idxs.push_back(i);
            i += 3; // skip a bit
        }
    }
    return idxs;
}

static fs::path safe_out_path(const fs::path& out_dir, const std::string& name, bool keep_paths) {
    std::string norm = name;
    std::replace(norm.begin(), norm.end(), '\\', '/');

    if (!keep_paths) {
        std::string flat = norm;
        std::replace(flat.begin(), flat.end(), '/', '_');
        if (flat.empty()) flat = "unnamed.bin";
        return out_dir / fs::path(flat);
    }

    // Keep folder structure but sanitize
    // - drop absolute roots
    // - remove ".." and empty segments
    // - ensure final canonical path stays inside out_dir
    std::vector<std::string> parts;
    parts.reserve(16);

    // Split by '/'
    size_t start = 0;
    while (start <= norm.size()) {
        size_t pos = norm.find('/', start);
        std::string seg = (pos == std::string::npos) ? norm.substr(start) : norm.substr(start, pos - start);
        start = (pos == std::string::npos) ? norm.size() + 1 : pos + 1;

        if (seg.empty() || seg == ".") continue;
        if (seg == "..") continue;

        // reject drive-like segment "C:" etc at the beginning
        if (parts.empty() && seg.size() == 2 && std::isalpha((unsigned char)seg[0]) && seg[1] == ':') {
            continue;
        }
        parts.push_back(seg);
    }

    fs::path rel;
    if (parts.empty()) rel = fs::path("unnamed.bin");
    else {
        for (const auto& s : parts) rel /= fs::path(s);
    }

    fs::path out_path = out_dir / rel;

    // Final safety: resolve/weakly_canonical and ensure it's within out_dir
    try {
        fs::path out_dir_res = fs::weakly_canonical(out_dir);
        fs::path out_path_res = fs::weakly_canonical(out_path);
        auto out_dir_it = out_dir_res.begin();
        auto out_path_it = out_path_res.begin();

        // Check prefix
        for (; out_dir_it != out_dir_res.end(); ++out_dir_it, ++out_path_it) {
            if (out_path_it == out_path_res.end() || *out_dir_it != *out_path_it) {
                // fallback to flattened
                std::string flat = norm;
                std::replace(flat.begin(), flat.end(), '/', '_');
                if (flat.empty()) flat = "unnamed.bin";
                return out_dir / fs::path(flat);
            }
        }
    } catch (...) {
        // If canonicalization fails, still return out_path (best effort)
    }

    return out_path;
}

static std::vector<uint8_t> ensure_vgbd_container(
    const std::vector<uint8_t>& raw_input,
    const fs::path* decoded_out_path // nullptr if not saving
) {
    if (starts_with_magic(raw_input, VGBD_MAGIC)) {
        return raw_input; // already decrypted container
    }

    std::vector<uint8_t> decrypted = decrypt_payload(raw_input);

    if (decoded_out_path) {
        write_file(*decoded_out_path, decrypted);
    }

    if (!starts_with_magic(decrypted, VGBD_MAGIC)) {
        throw std::runtime_error("After decrypt, result is NOT a VGBD container. Check input file / decrypt algorithm.");
    }
    return decrypted;
}

static std::vector<uint8_t> decompress_zstd_frame(const uint8_t* data, size_t size) {
    // Prefer known content size if available.
    unsigned long long contentSize = ZSTD_getFrameContentSize(data, size);
    if (contentSize != ZSTD_CONTENTSIZE_ERROR && contentSize != ZSTD_CONTENTSIZE_UNKNOWN) {
        std::vector<uint8_t> out((size_t)contentSize);
        size_t res = ZSTD_decompress(out.data(), out.size(), data, size);
        if (ZSTD_isError(res)) {
            throw std::runtime_error(std::string("ZSTD_decompress failed: ") + ZSTD_getErrorName(res));
        }
        // res should equal contentSize, but some frames may report slightly differently; trim to res.
        out.resize(res);
        return out;
    }

    // Streaming fallback
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) throw std::runtime_error("ZSTD_createDCtx failed.");

    std::vector<uint8_t> out;
    out.reserve(1024 * 1024);

    ZSTD_inBuffer inBuf { data, size, 0 };
    const size_t outChunkSize = ZSTD_DStreamOutSize();
    std::vector<uint8_t> outChunk(outChunkSize);

    while (inBuf.pos < inBuf.size) {
        ZSTD_outBuffer outBuf { outChunk.data(), outChunk.size(), 0 };
        size_t r = ZSTD_decompressStream(dctx, &outBuf, &inBuf);
        if (ZSTD_isError(r)) {
            ZSTD_freeDCtx(dctx);
            throw std::runtime_error(std::string("ZSTD_decompressStream failed: ") + ZSTD_getErrorName(r));
        }
        if (outBuf.pos > 0) {
            size_t oldSize = out.size();
            out.resize(oldSize + outBuf.pos);
            std::memcpy(out.data() + oldSize, outChunk.data(), outBuf.pos);
        }
        // r == 0 means end of frame reached (but we may still have extra bytes; in our use, frame is bounded)
        if (r == 0) break;
    }

    ZSTD_freeDCtx(dctx);
    return out;
}

struct Options {
    fs::path input;
    fs::path out_dir = "out_dir";
    bool list_only = false;
    bool keep_paths = false;
    bool save_decoded = false;
    fs::path decoded_out;
};

static void unpack_container(const std::vector<uint8_t>& container, const Options& opt) {
    if (!starts_with_magic(container, VGBD_MAGIC)) {
        throw std::runtime_error("Not a VGBD container (missing magic 'VGBD').");
    }
    if (container.size() < 0x24) {
        throw std::runtime_error("VGBD file too short (header truncated).");
    }

    uint32_t count = read_u32_le(container, 0x18);
    uint32_t names_offset = read_u32_le(container, 0x20);

    if (names_offset == 0 || names_offset >= container.size()) {
        throw std::runtime_error("Bad names table offset: " + std::to_string(names_offset));
    }

    auto names = parse_names(container, names_offset, count);
    auto frames = find_frames(container, (size_t)names_offset);

    if (frames.empty()) {
        throw std::runtime_error("No Zstandard frames found before the names table.");
    }

    if (frames.size() != names.size()) {
        std::cerr << "WARNING: frames(" << frames.size() << ") != names(" << names.size() << "). Will unpack min().\n";
    }

    size_t n = std::min(frames.size(), names.size());

    if (opt.list_only) {
        std::cout << "VGBD container: count(header)=" << count
                  << ", names_off=0x" << std::hex << names_offset << std::dec
                  << ", frames_found=" << frames.size() << "\n\n";
        for (size_t i = 0; i < n; ++i) {
            size_t start = frames[i];
            size_t end = (i + 1 < frames.size()) ? frames[i + 1] : (size_t)names_offset;
            std::cout << std::setw(4) << std::setfill('0') << i << "  "
                      << names[i] << "  frame_off=0x" << std::hex << start << std::dec
                      << "  comp_len=" << (end - start) << "\n";
        }
        return;
    }

    fs::create_directories(opt.out_dir);

    for (size_t i = 0; i < n; ++i) {
        size_t start = frames[i];
        size_t end = (i + 1 < frames.size()) ? frames[i + 1] : (size_t)names_offset;
        if (end > container.size() || start >= end) {
            throw std::runtime_error("Invalid frame bounds for entry " + std::to_string(i));
        }

        const uint8_t* chunk = container.data() + start;
        size_t chunkSize = end - start;

        std::vector<uint8_t> raw;
        try {
            raw = decompress_zstd_frame(chunk, chunkSize);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Zstd decompress failed for entry ") + std::to_string(i) +
                                     " (" + names[i] + ") at 0x" + [] (size_t x) {
                                        char b[32]; std::snprintf(b, sizeof(b), "%zx", x); return std::string(b);
                                     }(start) + ": " + e.what());
        }

        fs::path outPath = safe_out_path(opt.out_dir, names[i], opt.keep_paths);
        write_file(outPath, raw);
    }

    std::cout << "Unpacked " << n << " files into: " << opt.out_dir.string() << "\n";
}

static void print_usage() {
    std::cout <<
R"(vgbd_unpack_decode - Decrypt (XOR) + unpack VGBD .img (Zstandard frames)

Usage:
  vgbd_unpack_decode <input.img> -o <out_dir> [--list] [--decoded-out <file>] [--keep-paths]

Options:
  -o, --out <dir>           Output directory (default: out_dir)
  --list                    Only list entries (do not extract)
  --decoded-out <file>      Save decrypted VGBD container to this file (optional)
  --keep-paths              Keep folder structure from names table (sanitized)

Notes:
  - Auto-detects: if input starts with "VGBD", decrypt is skipped.
  - Otherwise the program skips first 4 bytes and decrypts the rest with XOR key 255 - (i % 255).
)";
}

static Options parse_args(int argc, char** argv) {
    Options opt;
    if (argc < 2) {
        print_usage();
        std::exit(2);
    }

    bool input_set = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "-h" || a == "--help") {
            print_usage();
            std::exit(0);
        } else if (a == "-o" || a == "--out") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --out");
            opt.out_dir = fs::path(argv[++i]);
        } else if (a == "--list") {
            opt.list_only = true;
        } else if (a == "--decoded-out") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --decoded-out");
            opt.save_decoded = true;
            opt.decoded_out = fs::path(argv[++i]);
        } else if (a == "--keep-paths") {
            opt.keep_paths = true;
        } else if (!input_set && !a.empty() && a[0] != '-') {
            opt.input = fs::path(a);
            input_set = true;
        } else {
            throw std::runtime_error("Unknown argument: " + a);
        }
    }

    if (!input_set) throw std::runtime_error("Input file is required.");
    return opt;
}

int main(int argc, char** argv) {
    try {
        Options opt = parse_args(argc, argv);

        std::vector<uint8_t> raw_input = read_file(opt.input);

        std::vector<uint8_t> container;
        if (opt.save_decoded) {
            container = ensure_vgbd_container(raw_input, &opt.decoded_out);
        } else {
            container = ensure_vgbd_container(raw_input, nullptr);
        }

        unpack_container(container, opt);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
