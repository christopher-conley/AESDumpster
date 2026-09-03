#include "KeyDumpster.h"
#include "../Platform/Console.h"
#include <unordered_set>
#include <cstring>
#include <cmath>
#include <cfloat>
#include <iostream>

KeyDumpster::KeyDumpster()
{
#if defined _DEBUG
  std::cout << "KeyDumpster Constructed." << std::endl;
#else
#endif
}

// Find patter in memory buffer.
std::vector<PBYTE> KeyDumpster::Find(const char* pattern, PBYTE rangeStart, PBYTE rangeEnd) {

  std::vector<PBYTE> keyLocations;
  const unsigned char* pat = reinterpret_cast<const unsigned char*>(pattern);
  PBYTE firstMatch = 0;
  for (PBYTE pCur = rangeStart; pCur < rangeEnd; ++pCur) {
    if (*(PBYTE)pat == (BYTE)'\?' || *pCur == getByte(pat)) {
      if (!firstMatch) firstMatch = pCur;
      pat += (*(PWORD)pat == (WORD)'\?\?' || *(PBYTE)pat != (BYTE)'\?') ? 2 : 1;
      if (!*pat) {
        keyLocations.push_back(firstMatch);
        continue;
      }
      pat++;
      if (!*pat) {
        keyLocations.push_back(firstMatch);
        continue;
      }
    }
    else if (firstMatch) {
      pCur = firstMatch;
      pat = reinterpret_cast<const unsigned char*>(pattern);
      firstMatch = 0;
    }
  }
  return keyLocations;
}

// Locate .text/.rdata ranges (raw file offsets) in a PE image, if the buffer
// looks like one. Parses the on-disk PE layout by hand instead of casting
// through <Windows.h> structures, so this works the same on every host
// platform; only recognizes x64 (PE32+) images, matching the pattern set
// below.
std::vector<std::pair<PBYTE, PBYTE>> KeyDumpster::GetScannableSections(char* buffer, uint64_t size) {

  std::vector<std::pair<PBYTE, PBYTE>> ranges;

  auto readU16 = [](const char* p) { uint16_t v; std::memcpy(&v, p, 2); return v; };
  auto readU32 = [](const char* p) { uint32_t v; std::memcpy(&v, p, 4); return v; };
  auto readI32 = [](const char* p) { int32_t v; std::memcpy(&v, p, 4); return v; };

  constexpr uint16_t kDosSignature = 0x5A4D;    // "MZ"
  constexpr uint32_t kNtSignature = 0x00004550; // "PE\0\0"
  constexpr uint16_t kOptHdr64Magic = 0x020B;   // PE32+
  constexpr uint64_t kSectionHeaderSize = 40;

  if (size < 0x40) return ranges;
  if (readU16(buffer) != kDosSignature) return ranges;

  int32_t ntOffsetSigned = readI32(buffer + 0x3C);
  if (ntOffsetSigned < 0) return ranges;
  uint64_t ntOffset = static_cast<uint64_t>(ntOffsetSigned);

  // Signature(4) + IMAGE_FILE_HEADER(20) + OptionalHeader Magic(2).
  if (ntOffset + 26 > size) return ranges;
  if (readU32(buffer + ntOffset) != kNtSignature) return ranges;

  uint16_t numberOfSections = readU16(buffer + ntOffset + 4 + 2);
  uint16_t sizeOfOptionalHeader = readU16(buffer + ntOffset + 4 + 16);
  uint16_t optionalHeaderMagic = readU16(buffer + ntOffset + 24);
  if (optionalHeaderMagic != kOptHdr64Magic) return ranges;

  uint64_t sectionTableOffset = ntOffset + 24 + sizeOfOptionalHeader;

  for (uint16_t i = 0; i < numberOfSections; ++i) {
    uint64_t sectionOffset = sectionTableOffset + (uint64_t)i * kSectionHeaderSize;
    if (sectionOffset + kSectionHeaderSize > size) break;

    const char* name = buffer + sectionOffset;
    bool isCode = std::strncmp(name, ".text", 5) == 0;
    bool isRData = std::strncmp(name, ".rdata", 6) == 0;
    if (!isCode && !isRData) continue;

    uint32_t sizeOfRawData = readU32(buffer + sectionOffset + 16);
    uint32_t pointerToRawData = readU32(buffer + sectionOffset + 20);
    if (pointerToRawData == 0 || sizeOfRawData == 0 ||
        (uint64_t)pointerToRawData + sizeOfRawData > size) continue;

    ranges.emplace_back(reinterpret_cast<PBYTE>(buffer + pointerToRawData),
                         reinterpret_cast<PBYTE>(buffer + pointerToRawData + sizeOfRawData));
  }
  return ranges;
}

// Pull the 32 raw key bytes for a match out of the exe buffer.
std::array<uint8_t, 32> KeyDumpster::ExtractKeyBytes(PBYTE keyAddr, int type) {
  std::array<uint8_t, 32> bytes{};
  for (size_t i = 0; i < m_keyDwordOffsets[type].size(); i++) {
    std::memcpy(&bytes[i * 4], &keyAddr[m_keyDwordOffsets[type][i]], 4);
  }
  return bytes;
}

// See declaration: flags candidates that look like float constant tables
// rather than key material.
bool KeyDumpster::LooksLikeFloatConstantTable(const std::array<uint8_t, 32>& keyBytes) const {
  int plausibleCount = 0;
  for (int i = 0; i < 8; ++i) {
    float f;
    std::memcpy(&f, &keyBytes[i * 4], sizeof(f));
    if (std::isfinite(f) && std::fabs(f) < 1000.0f) {
      ++plausibleCount;
    }
  }
  // A uniformly random dword has only a small chance of parsing as a small,
  // finite float, so requiring nearly all 8 to do so is safe against
  // flagging genuine (high-entropy) key material.
  return plausibleCount >= 7;
}

// AES String concatenator type
std::string KeyDumpster::ConcatenateAESType(PBYTE keyAddr, int type) {

  std::string hex_string = "";
  for (size_t i = 0; i < m_keyDwordOffsets[type].size(); i++) {
    hex_string += hexStr(&keyAddr[m_keyDwordOffsets[type][i]], 4);
  }
  std::transform(hex_string.begin(), hex_string.end(), hex_string.begin(), ::toupper);
  return hex_string;
}

// Run every pattern against every given range; filter, dedup (preserving
// discovery order) and score what's left.
bool KeyDumpster::ScanRanges(char* buffer, const std::vector<std::pair<PBYTE, PBYTE>>& ranges) {

  std::unordered_set<std::string> seen;

  for (size_t i = 0; i < m_keyPatterns.size(); i++) {
    for (const auto& range : ranges) {
      std::vector<PBYTE> matches = Find(m_keyPatterns[i].c_str(), range.first, range.second);
      for (size_t j = 0; j < matches.size(); j++) {
        std::string hex = ConcatenateAESType(matches[j], (int)i);
        if (seen.count(hex)) continue;

        std::array<uint8_t, 32> bytes = ExtractKeyBytes(matches[j], (int)i);
        if (std::find(m_falsePositives.begin(), m_falsePositives.end(), hex) != m_falsePositives.end()) continue;
        if (LooksLikeFloatConstantTable(bytes)) continue;

        seen.insert(hex);
        m_keys.m_keyvector.push_back(Key(hex));
      }
    }
  }

  // Generate entropy score for each key.
  m_keyEntropies = KeyEntropyGenerator(m_keys);
  m_MostLikelyKey = FindMaxElements(m_keyEntropies).second;

  return !(m_keyEntropies.empty() || m_MostLikelyKey.empty() || m_keys.getKeys().empty());
}

//Scan memory aes key buffer and extract the individual dword key buffers.
bool KeyDumpster::FindAESKeys(char* buffer, uint64_t size) {

  std::vector<std::pair<PBYTE, PBYTE>> sections = GetScannableSections(buffer, size);

  if (!sections.empty() && ScanRanges(buffer, sections)) {
    return true;
  }

  // Either not a recognizable PE image, or nothing turned up in
  // .text/.rdata - fall back to scanning the whole file like before.
  std::vector<std::pair<PBYTE, PBYTE>> wholeBuffer = {
    { reinterpret_cast<PBYTE>(buffer), reinterpret_cast<PBYTE>(buffer) + size }
  };
  return ScanRanges(buffer, wholeBuffer);
}

//Generate aes key entropy score.
std::vector<double> KeyDumpster::KeyEntropyGenerator(Keys keys) {

  std::vector<double> keyEntropies{};
  for (size_t i = 0; i < keys.getKeys().size(); i++) {
    keyEntropies.push_back(CalcEntropy(keys.getKeys()[i].getKey()));
  }
  return keyEntropies;
}

// print key information.
bool KeyDumpster::PrintKeyInformation() {

  for (size_t i = 0; i < m_keys.getKeys().size(); i++) {

    if (m_keyEntropies[i] >= 3.3 && m_keyEntropies[i] < 3.4) {
      SetConsoleColor(ConsoleColor::Red);
    }
    else if (m_keyEntropies[i] >= 3.4 && m_keyEntropies[i] < 3.5) {
      SetConsoleColor(ConsoleColor::Brown);
    }
    else if (m_keyEntropies[i] >= 3.5 && m_keyEntropies[i] < 3.7) {
      SetConsoleColor(ConsoleColor::Yellow);
    }
    else if (m_keyEntropies[i] >= 3.7) {
      SetConsoleColor(ConsoleColor::Green);
    }

    for (size_t j = 0; j < m_MostLikelyKey.size(); j++) {
      if (i == m_MostLikelyKey[j]) {
        SetConsoleColor(ConsoleColor::Green);
      }
    }
    // Blacklist/heuristic filtering already happened at collection time
    // (ScanRanges), so everything left here is worth showing above the
    // entropy floor.
    if (m_keyEntropies[i] >= 3.3) {
      printf("Key: 0x%s | Key Entropy: %f\n\n", m_keys.getKeys()[i].getKey().c_str(), m_keyEntropies[i]);
    }
    SetConsoleColor(ConsoleColor::Default);
  }
  return true;
}

// log2 from: https://tfetimes.com/c-entropy/
double KeyDumpster::log2_intrinsic(double number) {
  return log(number) / log(2);
}

// hexStr from stackoverflow: https://stackoverflow.com/questions/14050452/how-to-convert-byte-array-to-hex-string-in-visual-c
std::string KeyDumpster::hexStr(const uint8_t* data, int len) {

  std::stringstream ss;
  ss << std::hex;

  for (int i(0); i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  return ss.str();
}

// Calculate entropy score on AES keys.
double KeyDumpster::CalcEntropy(std::string keyString) {

  std::map<char, int> frequencies;
  for (char c : keyString)
    frequencies[c]++;

  size_t numlen = keyString.length();
  double infocontent = 0;
  for (std::pair<char, int> p : frequencies) {
    double freq = static_cast<double>(p.second) / numlen;
    infocontent += freq * log2_intrinsic(freq);
  }
  infocontent *= -1;
  return infocontent;
}

// Find the biggest double value in a vector.
std::pair<double, std::vector<std::size_t>> KeyDumpster::FindMaxElements(std::vector<double> const& v) {

  std::vector<std::size_t> indices;
  double current_max = -DBL_MAX;

  for (std::size_t i = 0; i < v.size(); ++i) {
    if (v[i] > current_max) {
      current_max = v[i];
      indices.clear();
    }

    if (v[i] == current_max) {
      indices.push_back(i);
    }
  }
  return std::make_pair(current_max, indices);
}

//Destructor.
KeyDumpster::~KeyDumpster()
{
  m_keyEntropies.clear();
  m_MostLikelyKey.clear();

#if defined _DEBUG
  std::cout << "KeyDumpster Destructed." << std::endl;
#else
#endif
}
