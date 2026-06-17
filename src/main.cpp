#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>

static std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == name) {
            return argv[i + 1];
        }
    }
    return "";
}

static void print_usage() {
    std::cout << "sigtool - Lab 5 Classical Digital Signatures\n\n";
    std::cout << "Usage:\n";
    std::cout << "  sigtool --version\n";
    std::cout << "  sigtool keygen --algo ecdsa-p256 --pub keys/ecdsa_pub.pem --priv keys/ecdsa_priv.pem\n";
    std::cout << "  sigtool keygen --algo rsa-pss-3072 --pub keys/rsa_pub.pem --priv keys/rsa_priv.pem\n";
    std::cout << "  sigtool sign --algo ecdsa-p256 --in msg.bin --priv priv.pem --out sig.bin --hash sha256 --encode raw\n";
    std::cout << "  sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem --hash sha256 --encode raw\n";
    std::cout << "  sigtool sign --algo rsa-pss-3072 --in msg.bin --priv priv.pem --out sig.bin --hash sha256 --encode raw\n";
    std::cout << "  sigtool verify --algo rsa-pss-3072 --in msg.bin --sig sig.bin --pub pub.pem --hash sha256 --encode raw\n\n";
    std::cout << "Supported algorithms:\n";
    std::cout << "  ecdsa-p256\n";
    std::cout << "  rsa-pss-3072\n\n";
    std::cout << "Supported signature encodings:\n";
    std::cout << "  raw, hex, base64\n";
}

static void print_openssl_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
    ERR_print_errors_fp(stderr);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static bool ends_with_lower(const std::string& path, const std::string& ext) {
    std::string p = to_lower(path);
    std::string e = to_lower(ext);

    if (p.size() < e.size()) {
        return false;
    }

    return p.substr(p.size() - e.size()) == e;
}

static bool read_binary_file(const std::string& path, std::vector<unsigned char>& data) {
    std::ifstream in(path, std::ios::binary);

    if (!in) {
        std::cerr << "[ERROR] Cannot open input file: " << path << "\n";
        return false;
    }

    data.assign(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    );

    return true;
}

static bool write_binary_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::filesystem::path p(path);

    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path());
    }

    std::ofstream out(path, std::ios::binary);

    if (!out) {
        std::cerr << "[ERROR] Cannot open output file: " << path << "\n";
        return false;
    }

    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return true;
}

static bool write_text_file(const std::string& path, const std::string& text) {
    std::filesystem::path p(path);

    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path());
    }

    std::ofstream out(path, std::ios::binary);

    if (!out) {
        std::cerr << "[ERROR] Cannot open output file: " << path << "\n";
        return false;
    }

    out << text;
    return true;
}

static std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;

    for (unsigned char b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return oss.str();
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

static bool hex_to_bytes(const std::string& hex, std::vector<unsigned char>& out) {
    std::string clean;

    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean.push_back(c);
        }
    }

    if (clean.size() % 2 != 0) {
        return false;
    }

    out.clear();
    out.reserve(clean.size() / 2);

    for (size_t i = 0; i < clean.size(); i += 2) {
        int hi = hex_value(clean[i]);
        int lo = hex_value(clean[i + 1]);

        if (hi < 0 || lo < 0) {
            return false;
        }

        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }

    return true;
}

static std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());

    if (!b64 || !mem) {
        BIO_free_all(b64);
        BIO_free_all(mem);
        return "";
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(b64, &buffer);

    std::string out;

    if (buffer && buffer->data && buffer->length > 0) {
        out.assign(buffer->data, buffer->length);
    }

    BIO_free_all(b64);
    return out;
}

static bool base64_decode(const std::string& text, std::vector<unsigned char>& out) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(text.data(), static_cast<int>(text.size()));

    if (!b64 || !mem) {
        BIO_free_all(b64);
        BIO_free_all(mem);
        return false;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    out.assign(text.size(), 0);

    int len = BIO_read(b64, out.data(), static_cast<int>(out.size()));

    if (len < 0) {
        BIO_free_all(b64);
        return false;
    }

    out.resize(static_cast<size_t>(len));
    BIO_free_all(b64);
    return true;
}

static bool write_signature_file(
    const std::string& out_path,
    const std::vector<unsigned char>& sig,
    const std::string& encode
) {
    if (encode == "raw") {
        return write_binary_file(out_path, sig);
    }

    if (encode == "hex") {
        return write_text_file(out_path, bytes_to_hex(sig) + "\n");
    }

    if (encode == "base64") {
        return write_text_file(out_path, base64_encode(sig) + "\n");
    }

    std::cerr << "[ERROR] Unsupported encoding: " << encode << "\n";
    return false;
}

static bool read_signature_file(
    const std::string& sig_path,
    std::vector<unsigned char>& sig,
    const std::string& encode
) {
    if (encode == "raw") {
        return read_binary_file(sig_path, sig);
    }

    std::vector<unsigned char> text_bytes;

    if (!read_binary_file(sig_path, text_bytes)) {
        return false;
    }

    std::string text(text_bytes.begin(), text_bytes.end());

    if (encode == "hex") {
        if (!hex_to_bytes(text, sig)) {
            std::cerr << "[ERROR] Invalid hex signature file.\n";
            return false;
        }

        return true;
    }

    if (encode == "base64") {
        if (!base64_decode(text, sig)) {
            std::cerr << "[ERROR] Invalid base64 signature file.\n";
            return false;
        }

        return true;
    }

    std::cerr << "[ERROR] Unsupported encoding: " << encode << "\n";
    return false;
}

static bool write_private_key(EVP_PKEY* pkey, const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "wb");

    if (!bio) {
        print_openssl_error("Cannot open private key output");
        return false;
    }

    bool ok = false;

    if (ends_with_lower(path, ".der")) {
        ok = i2d_PrivateKey_bio(bio, pkey) == 1;
    } else {
        ok = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    }

    BIO_free(bio);

    if (!ok) {
        print_openssl_error("Cannot write private key");
        return false;
    }

    return true;
}

static bool write_public_key(EVP_PKEY* pkey, const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "wb");

    if (!bio) {
        print_openssl_error("Cannot open public key output");
        return false;
    }

    bool ok = false;

    if (ends_with_lower(path, ".der")) {
        ok = i2d_PUBKEY_bio(bio, pkey) == 1;
    } else {
        ok = PEM_write_bio_PUBKEY(bio, pkey) == 1;
    }

    BIO_free(bio);

    if (!ok) {
        print_openssl_error("Cannot write public key");
        return false;
    }

    return true;
}

static EVP_PKEY* load_private_key(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");

    if (!bio) {
        print_openssl_error("Cannot open private key");
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (pkey) {
        return pkey;
    }

    ERR_clear_error();

    bio = BIO_new_file(path.c_str(), "rb");

    if (!bio) {
        print_openssl_error("Cannot reopen private key");
        return nullptr;
    }

    pkey = d2i_PrivateKey_bio(bio, nullptr);
    BIO_free(bio);

    if (!pkey) {
        print_openssl_error("Cannot parse private key as PEM or DER");
    }

    return pkey;
}

static EVP_PKEY* load_public_key(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");

    if (!bio) {
        print_openssl_error("Cannot open public key");
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (pkey) {
        return pkey;
    }

    ERR_clear_error();

    bio = BIO_new_file(path.c_str(), "rb");

    if (!bio) {
        print_openssl_error("Cannot reopen public key");
        return nullptr;
    }

    pkey = d2i_PUBKEY_bio(bio, nullptr);
    BIO_free(bio);

    if (!pkey) {
        print_openssl_error("Cannot parse public key as PEM or DER");
    }

    return pkey;
}

static std::string key_type_string(EVP_PKEY* pkey) {
    if (!pkey) {
        return "(null)";
    }

    int id = EVP_PKEY_base_id(pkey);

    if (id == EVP_PKEY_EC) {
        return "EC";
    }

    if (id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS) {
        return "RSA";
    }

    return "Unsupported";
}

static bool validate_hash(const std::string& hash) {
    return hash.empty() || hash == "sha256";
}

static bool validate_algo_key(EVP_PKEY* pkey, const std::string& algo) {
    int id = EVP_PKEY_base_id(pkey);

    if (algo == "ecdsa-p256") {
        if (id != EVP_PKEY_EC) {
            std::cerr << "[ERROR] Algorithm/key mismatch: expected EC key for ECDSA-P256.\n";
            return false;
        }

        return true;
    }

    if (algo == "rsa-pss-3072") {
        if (id != EVP_PKEY_RSA && id != EVP_PKEY_RSA_PSS) {
            std::cerr << "[ERROR] Algorithm/key mismatch: expected RSA key for RSA-PSS.\n";
            return false;
        }

        return true;
    }

    std::cerr << "[ERROR] Unsupported algorithm: " << algo << "\n";
    return false;
}

static bool configure_pss_if_needed(EVP_PKEY_CTX* pctx, const std::string& algo) {
    if (algo != "rsa-pss-3072") {
        return true;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        print_openssl_error("Cannot set RSA-PSS padding");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        print_openssl_error("Cannot set RSA-PSS MGF1 SHA-256");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) <= 0) {
        print_openssl_error("Cannot set RSA-PSS salt length");
        return false;
    }

    return true;
}

static bool keygen_ecdsa_p256(const std::string& pub_path, const std::string& priv_path) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    if (!ctx) {
        print_openssl_error("EVP_PKEY_CTX_new_id EC failed");
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    bool ok = false;

    do {
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            print_openssl_error("EC keygen init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
            print_openssl_error("Cannot set curve prime256v1");
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            print_openssl_error("EC keygen failed");
            break;
        }

        if (!write_public_key(pkey, pub_path)) {
            break;
        }

        if (!write_private_key(pkey, priv_path)) {
            break;
        }

        std::cout << "\n>> KEYGEN RESULT <<\n";
        std::cout << "Algorithm       : ECDSA-P256\n";
        std::cout << "Curve           : prime256v1 / secp256r1\n";
        std::cout << "Public key      : " << pub_path << "\n";
        std::cout << "Private key     : " << priv_path << "\n";
        std::cout << "Key format      : " << (ends_with_lower(pub_path, ".der") ? "DER" : "PEM") << "\n";

        ok = true;

    } while (false);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static bool keygen_rsa_pss_3072(const std::string& pub_path, const std::string& priv_path) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx) {
        print_openssl_error("EVP_PKEY_CTX_new_id RSA failed");
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    bool ok = false;

    do {
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            print_openssl_error("RSA keygen init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
            print_openssl_error("Cannot set RSA key size");
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            print_openssl_error("RSA keygen failed");
            break;
        }

        if (!write_public_key(pkey, pub_path)) {
            break;
        }

        if (!write_private_key(pkey, priv_path)) {
            break;
        }

        std::cout << "\n>> KEYGEN RESULT <<\n";
        std::cout << "Algorithm       : RSA-PSS-3072\n";
        std::cout << "Modulus bits    : " << EVP_PKEY_bits(pkey) << "\n";
        std::cout << "Hash            : SHA-256\n";
        std::cout << "PSS salt length : 32 bytes\n";
        std::cout << "Public key      : " << pub_path << "\n";
        std::cout << "Private key     : " << priv_path << "\n";
        std::cout << "Key format      : " << (ends_with_lower(pub_path, ".der") ? "DER" : "PEM") << "\n";

        ok = true;

    } while (false);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static bool sign_file(
    const std::string& algo,
    const std::string& in_path,
    const std::string& priv_path,
    const std::string& out_path,
    const std::string& hash,
    const std::string& encode
) {
    if (!validate_hash(hash)) {
        std::cerr << "[ERROR] Only SHA-256 is supported for Lab 5.\n";
        return false;
    }

    std::vector<unsigned char> message;

    if (!read_binary_file(in_path, message)) {
        return false;
    }

    EVP_PKEY* pkey = load_private_key(priv_path);

    if (!pkey) {
        return false;
    }

    if (!validate_algo_key(pkey, algo)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();

    if (!mctx) {
        EVP_PKEY_free(pkey);
        print_openssl_error("EVP_MD_CTX_new failed");
        return false;
    }

    EVP_PKEY_CTX* pctx = nullptr;
    std::vector<unsigned char> sig;
    bool ok = false;

    do {
        if (EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, pkey) <= 0) {
            print_openssl_error("EVP_DigestSignInit failed");
            break;
        }

        if (!configure_pss_if_needed(pctx, algo)) {
            break;
        }

        if (!message.empty()) {
            if (EVP_DigestSignUpdate(mctx, message.data(), message.size()) <= 0) {
                print_openssl_error("EVP_DigestSignUpdate failed");
                break;
            }
        }

        size_t sig_len = 0;

        if (EVP_DigestSignFinal(mctx, nullptr, &sig_len) <= 0) {
            print_openssl_error("EVP_DigestSignFinal size failed");
            break;
        }

        sig.resize(sig_len);

        if (EVP_DigestSignFinal(mctx, sig.data(), &sig_len) <= 0) {
            print_openssl_error("EVP_DigestSignFinal failed");
            break;
        }

        sig.resize(sig_len);

        if (!write_signature_file(out_path, sig, encode)) {
            break;
        }

        std::cout << "\n>> SIGN RESULT <<\n";
        std::cout << "Algorithm       : " << algo << "\n";
        std::cout << "Hash            : SHA-256\n";
        std::cout << "Input file      : " << in_path << "\n";
        std::cout << "Private key     : " << priv_path << "\n";
        std::cout << "Message size    : " << message.size() << " bytes\n";
        std::cout << "Signature size  : " << sig.size() << " bytes\n";
        std::cout << "Signature output: " << out_path << "\n";
        std::cout << "Encoding        : " << encode << "\n";

        if (algo == "rsa-pss-3072") {
            std::cout << "PSS salt length : 32 bytes\n";
        }

        ok = true;

    } while (false);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static bool verify_file(
    const std::string& algo,
    const std::string& in_path,
    const std::string& sig_path,
    const std::string& pub_path,
    const std::string& hash,
    const std::string& encode
) {
    if (!validate_hash(hash)) {
        std::cerr << "[ERROR] Only SHA-256 is supported for Lab 5.\n";
        return false;
    }

    std::vector<unsigned char> message;
    std::vector<unsigned char> sig;

    if (!read_binary_file(in_path, message)) {
        return false;
    }

    if (!read_signature_file(sig_path, sig, encode)) {
        return false;
    }

    EVP_PKEY* pkey = load_public_key(pub_path);

    if (!pkey) {
        return false;
    }

    if (!validate_algo_key(pkey, algo)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();

    if (!mctx) {
        EVP_PKEY_free(pkey);
        print_openssl_error("EVP_MD_CTX_new failed");
        return false;
    }

    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = false;

    do {
        if (EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, pkey) <= 0) {
            print_openssl_error("EVP_DigestVerifyInit failed");
            break;
        }

        if (!configure_pss_if_needed(pctx, algo)) {
            break;
        }

        if (!message.empty()) {
            if (EVP_DigestVerifyUpdate(mctx, message.data(), message.size()) <= 0) {
                print_openssl_error("EVP_DigestVerifyUpdate failed");
                break;
            }
        }

        int result = EVP_DigestVerifyFinal(mctx, sig.data(), sig.size());

        std::cout << "\n>> VERIFY RESULT <<\n";
        std::cout << "Algorithm       : " << algo << "\n";
        std::cout << "Hash            : SHA-256\n";
        std::cout << "Input file      : " << in_path << "\n";
        std::cout << "Public key      : " << pub_path << "\n";
        std::cout << "Signature file  : " << sig_path << "\n";
        std::cout << "Message size    : " << message.size() << " bytes\n";
        std::cout << "Signature size  : " << sig.size() << " bytes\n";
        std::cout << "Encoding        : " << encode << "\n";

        if (result == 1) {
            std::cout << "Status          : VALID\n";
            ok = true;
        } else if (result == 0) {
            std::cout << "Status          : INVALID\n";
            ok = false;
        } else {
            print_openssl_error("Verification error");
            ok = false;
        }

    } while (false);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    std::string command = argv[1];

    if (command == "--version") {
        std::cout << "{\n";
        std::cout << "  \"tool\": \"sigtool\",\n";
        std::cout << "  \"lab\": \"Lab 5 - Classical Digital Signatures\",\n";
        std::cout << "  \"openssl\": \"" << OpenSSL_version(OPENSSL_VERSION) << "\",\n";
        std::cout << "  \"status\": \"environment ok\"\n";
        std::cout << "}\n";
        return 0;
    }

    if (command == "keygen") {
        std::string algo = get_arg(argc, argv, "--algo");
        std::string pub_path = get_arg(argc, argv, "--pub");
        std::string priv_path = get_arg(argc, argv, "--priv");

        if (algo.empty() || pub_path.empty() || priv_path.empty()) {
            std::cerr << "[ERROR] Missing --algo, --pub, or --priv.\n";
            print_usage();
            return 1;
        }

        algo = to_lower(algo);

        std::filesystem::create_directories(std::filesystem::path(pub_path).parent_path());
        std::filesystem::create_directories(std::filesystem::path(priv_path).parent_path());

        if (algo == "ecdsa-p256") {
            return keygen_ecdsa_p256(pub_path, priv_path) ? 0 : 1;
        }

        if (algo == "rsa-pss-3072") {
            return keygen_rsa_pss_3072(pub_path, priv_path) ? 0 : 1;
        }

        std::cerr << "[ERROR] Unsupported algorithm: " << algo << "\n";
        return 1;
    }

    if (command == "sign") {
        std::string algo = to_lower(get_arg(argc, argv, "--algo"));
        std::string in_path = get_arg(argc, argv, "--in");
        std::string priv_path = get_arg(argc, argv, "--priv");
        std::string out_path = get_arg(argc, argv, "--out");
        std::string hash = to_lower(get_arg(argc, argv, "--hash"));
        std::string encode = to_lower(get_arg(argc, argv, "--encode"));

        if (hash.empty()) {
            hash = "sha256";
        }

        if (encode.empty()) {
            encode = "raw";
        }

        if (algo.empty() || in_path.empty() || priv_path.empty() || out_path.empty()) {
            std::cerr << "[ERROR] Missing required sign arguments.\n";
            print_usage();
            return 1;
        }

        if (encode != "raw" && encode != "hex" && encode != "base64") {
            std::cerr << "[ERROR] Unsupported --encode. Use raw, hex, or base64.\n";
            return 1;
        }

        return sign_file(algo, in_path, priv_path, out_path, hash, encode) ? 0 : 1;
    }

    if (command == "verify") {
        std::string algo = to_lower(get_arg(argc, argv, "--algo"));
        std::string in_path = get_arg(argc, argv, "--in");
        std::string sig_path = get_arg(argc, argv, "--sig");
        std::string pub_path = get_arg(argc, argv, "--pub");
        std::string hash = to_lower(get_arg(argc, argv, "--hash"));
        std::string encode = to_lower(get_arg(argc, argv, "--encode"));

        if (hash.empty()) {
            hash = "sha256";
        }

        if (encode.empty()) {
            encode = "raw";
        }

        if (algo.empty() || in_path.empty() || sig_path.empty() || pub_path.empty()) {
            std::cerr << "[ERROR] Missing required verify arguments.\n";
            print_usage();
            return 1;
        }

        if (encode != "raw" && encode != "hex" && encode != "base64") {
            std::cerr << "[ERROR] Unsupported --encode. Use raw, hex, or base64.\n";
            return 1;
        }

        return verify_file(algo, in_path, sig_path, pub_path, hash, encode) ? 0 : 1;
    }

    std::cerr << "[ERROR] Unknown command: " << command << "\n";
    print_usage();
    return 1;
}
