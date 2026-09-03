#pragma once
#include <string>
#include <cstdint>
#include <filesystem>

#ifdef _WIN32
#include <Windows.h>
#endif

class OtherTools
{
public:
  OtherTools();
  void PrintIntro();
  void PrintInstructions();
  void PrintFileName(const std::filesystem::path& filepath);
  void PrintOutro();
  int CreateExeBuffer(const std::filesystem::path& filepath);
  // Releases whatever CreateExeBuffer handed back in retval (memory-mapped
  // view or heap buffer) and resets it. Callers must not free retval.buffer
  // themselves - the two allocation paths need different teardown calls.
  void ReleaseBuffer();
	~OtherTools();

public:
  struct RETVAL {
    char* buffer = nullptr;
    uint64_t size = 0;
    bool isMapped = false;
#ifdef _WIN32
    HANDLE mappingHandle = nullptr;
#endif
  } retval;

};
