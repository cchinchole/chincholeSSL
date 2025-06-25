#include "../../inc/crypto/aes.hpp"
#include "../../inc/hash/sha.hpp"
#include "../../inc/utils/bytes.hpp"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <regex>
#include <string>
#include <vector>

struct SiggenTest {
  std::string COUNT; // "Msg" or "MD"
  std::string KEY;
  std::string IV;
  std::string CIPHERTEXT;
  std::string PLAINTEXT;
};

struct CurveHashTests {
  std::string state;
  std::vector<SiggenTest> tests;
};

struct SiggenRsp {
  std::vector<CurveHashTests> curve_hash_tests;
};

static std::string trim(const std::string &s) {
  auto a = s.find_first_not_of(" \t\r\n");
  auto b = s.find_last_not_of(" \t\r\n");
  return (a == std::string::npos ? "" : s.substr(a, b - a + 1));
}

SiggenRsp parseSigGen(const std::string &filename) {
  SiggenRsp rsp;
  CurveHashTests current_ch;
  SiggenTest current_test;
  std::ifstream in(filename);
  std::string line;

  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty() || line.front() == '#')
      continue;

    auto brack = line.find('[');
    if (brack != std::string::npos) {
      auto endbracket = line.find(']');
      if (endbracket != std::string::npos) {
        std::string hsh = trim(line.substr(brack + 1, endbracket - brack - 1));
        // If there are any tests in the current test group, save it
        if (!current_test.COUNT.empty()) {
          current_ch.tests.push_back(current_test);
          current_test = SiggenTest{};
        }
        // If the current curve-hash pair has tests, save it
        if (!current_ch.tests.empty()) {
          rsp.curve_hash_tests.push_back(current_ch);
          current_ch = CurveHashTests{};
        }
        current_ch.state = hsh;
      }
      continue;
    }

    auto eq = line.find('=');
    if (eq == std::string::npos)
      continue;

    std::string key = trim(line.substr(0, eq));
    std::string val = trim(line.substr(eq + 1));

    if (key == "COUNT") {
      if (!current_test.COUNT.empty()) {
        current_ch.tests.push_back(current_test);
        current_test = SiggenTest();
      }
      current_test.COUNT = val;
    } else if (key == "KEY")
      current_test.KEY = val;
    else if (key == "IV")
      current_test.IV = val;
    else if (key == "CIPHERTEXT")
      current_test.CIPHERTEXT = val;
    else if (key == "PLAINTEXT")
      current_test.PLAINTEXT = val;
  }

  // Save the last test if it exists
  if (!current_test.COUNT.empty()) {
    current_ch.tests.push_back(current_test);
  }
  // Save the last curve-hash pair if it has tests
  if (!current_ch.tests.empty()) {
    rsp.curve_hash_tests.push_back(current_ch);
  }

  return rsp;
}

AES_MODE haveAES(std::string name) {
  if (name == "CBC192") {
    return AES_MODE::AES_CBC_192;
  } else if (name == "CBC256") {
    return AES_MODE::AES_CBC_256;
  } else if (name == "CBC128") {
    return AES_MODE::AES_CBC_128;
  }
    return AES_MODE::AES_CBC_256;
}

void runTest(std::string path, std::string fileName, AES_MODE mode, int *passed,
             int *failed) {
  auto rsp = parseSigGen(path + fileName);
  int pe = 0, fe = 0;
  int pd = 0, fd = 0;
  for (const auto &ch : rsp.curve_hash_tests) {
    for (const auto &t : ch.tests) {
      if (ch.state == "ENCRYPT") {
        AES_CTX *ctx = new AES_CTX();

        ctx->mode = mode;
        FIPS_197_5_2_KeyExpansion(ctx, hexToBytes(t.KEY).data());
        SetIV(ctx, hexToBytes(t.IV).data());

        std::vector<uint8_t> buffer = hexToBytes(t.PLAINTEXT);
        std::vector<uint8_t> output;
        output.resize(buffer.size());

        CBC_Encrypt(ctx, output.data(), buffer.data(), buffer.size());

        std::string hexOutput = bytesToHex(output);
        if (std::memcmp(output.data(), hexToBytes(t.CIPHERTEXT).data(),
                        output.size()) == 0)
          pe++;
        else
          fe++;
        delete ctx;
      } else if (ch.state == "DECRYPT") {
        AES_CTX *ctx = new AES_CTX();

        ctx->mode = mode;
        FIPS_197_5_2_KeyExpansion(ctx, hexToBytes(t.KEY).data());
        SetIV(ctx, hexToBytes(t.IV).data());

        std::vector<uint8_t> buffer = hexToBytes(t.CIPHERTEXT);
        std::vector<uint8_t> output;
        output.resize(buffer.size());

        CBC_Decrypt(ctx, output.data(), buffer.data(), buffer.size());

        if (std::memcmp(output.data(), hexToBytes(t.PLAINTEXT).data(),
                        output.size()) == 0)
          pd++;
        else
          fd++;

        delete ctx;
      }
    }
  }
  std::cout << "Result [ " << fileName << " ]: " << std::endl<<"Enc: "<< pe << " passed "<<fe<<" failed."<<std::endl<<"Dec: "<< pd << " passed " << fd << " failed." << std::endl << std::endl;
  *passed += (pe + pd);
  *failed += (fe + fd);
}

int main() {

  int tests_performed = 0;
  int passed = 0;
  int failed = 0;
  int test_files = 0;
  namespace fs = std::filesystem;
  std::string path = "./vectors/"; 
  try {

    if (!fs::exists(path) || !fs::is_directory(path)) {
      std::cerr << "Wrong directory";
      return 1;
    }

    std::regex key_size_regex("(128|192|256)\\.rsp$");
    for (const auto &entry : fs::directory_iterator(path)) {
      if (entry.path().extension() == ".rsp") {
        std::string fileName = entry.path().filename().string();

        std::string cipher = fileName.substr(0, 3);
        std::string key_size = "Not found";

        std::smatch match;
        if (std::regex_search(fileName, match, key_size_regex)) {
          key_size = match[1].str();
        }

        runTest(path, fileName, haveAES(cipher+key_size), &passed, &failed);
        tests_performed++;
      }
    }
  } catch (const fs::filesystem_error &e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }

  std::cout << "Results: " << passed << " passed " << failed << " failed."
            << std::endl;

  OPENSSL_cleanup();
  return 0;
}
