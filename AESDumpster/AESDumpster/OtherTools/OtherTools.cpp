#include "OtherTools.h"
#include "../Platform/Console.h"
#include <iostream>
#include <algorithm>
#include <cstdlib>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#endif

OtherTools::OtherTools()
{
}

void OtherTools::PrintIntro() {
  std::cout << "AESDumpster 1.2.5 - By GHFear @ IllusorySoftware\n";
  std::cout << "Supports Unreal Engine 4.19 -> 5.3 | (Will soon support UE 4.0 - 4.18 as well)\n\n";
}

void OtherTools::PrintInstructions() {
  std::cout << "Usage:\n";
  std::cout << "-Drag and drop Unreal Engine executables onto AESDumpster, or pass them as arguments.\n";
  std::cout << "-Wait for the tool to finish.\n";
  std::cin.ignore();
}

void OtherTools::PrintFileName(const std::filesystem::path& filepath) {
  SetConsoleColor(ConsoleColor::Yellow);
#ifdef _WIN32
  std::wcout << filepath.wstring() << std::endl;
#else
  std::cout << filepath.string() << std::endl;
#endif
  SetConsoleColor(ConsoleColor::Default);
}

void OtherTools::PrintOutro() {
  SetConsoleColor(ConsoleColor::Green);
  std::cout << "Done!\n";
  SetConsoleColor(ConsoleColor::Default);
}

int OtherTools::CreateExeBuffer(const std::filesystem::path& filepath) {

#ifdef _WIN32
  HANDLE hFile = CreateFileW(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    std::cerr << "Error opening exe file (GetLastError=" << GetLastError() << ").\n";
    return 1;
  }

  LARGE_INTEGER fileSize{};
  if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
    std::cerr << "Error getting exe file size (GetLastError=" << GetLastError() << ").\n";
    CloseHandle(hFile);
    return 1;
  }

  // Prefer a memory-mapped view - avoids reading the whole file (UE5
  // Shipping exes can run into the gigabytes) into a heap buffer up front.
  HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (hMapping != nullptr) {
    void* mapped = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (mapped != nullptr) {
      retval.buffer = static_cast<char*>(mapped);
      retval.size = static_cast<uint64_t>(fileSize.QuadPart);
      retval.isMapped = true;
      retval.mappingHandle = hMapping;
      CloseHandle(hFile); // The mapping keeps its own reference to the file.
      return 0;
    }
    CloseHandle(hMapping);
  }

  std::cerr << "Warning: memory mapping failed, falling back to a heap buffer.\n";

  char* file_buffer = static_cast<char*>(malloc(static_cast<size_t>(fileSize.QuadPart)));
  if (file_buffer == nullptr) {
    std::cerr << "Error allocating " << fileSize.QuadPart << " bytes for exe buffer.\n";
    CloseHandle(hFile);
    return 1;
  }

  uint64_t totalRead = 0;
  const uint64_t targetSize = static_cast<uint64_t>(fileSize.QuadPart);
  while (totalRead < targetSize) {
    DWORD toRead = static_cast<DWORD>(std::min<uint64_t>(targetSize - totalRead, 1ull << 30));
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, file_buffer + totalRead, toRead, &bytesRead, nullptr) || bytesRead == 0) {
      std::cerr << "Error reading exe file (GetLastError=" << GetLastError() << ").\n";
      free(file_buffer);
      CloseHandle(hFile);
      return 1;
    }
    totalRead += bytesRead;
  }
  CloseHandle(hFile);

  retval.buffer = file_buffer;
  retval.size = targetSize;
  retval.isMapped = false;
  retval.mappingHandle = nullptr;

  return 0;

#else // POSIX

  int fd = open(filepath.c_str(), O_RDONLY);
  if (fd < 0) {
    std::cerr << "Error opening exe file (" << std::strerror(errno) << ").\n";
    return 1;
  }

  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size == 0) {
    std::cerr << "Error getting exe file size (" << std::strerror(errno) << ").\n";
    close(fd);
    return 1;
  }
  const uint64_t targetSize = static_cast<uint64_t>(st.st_size);

  // Prefer a memory-mapped view - avoids reading the whole file (UE5
  // Shipping exes can run into the gigabytes) into a heap buffer up front.
  void* mapped = mmap(nullptr, targetSize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mapped != MAP_FAILED) {
    retval.buffer = static_cast<char*>(mapped);
    retval.size = targetSize;
    retval.isMapped = true;
    close(fd); // The mapping keeps its own reference to the file.
    return 0;
  }

  std::cerr << "Warning: memory mapping failed, falling back to a heap buffer.\n";

  char* file_buffer = static_cast<char*>(malloc(static_cast<size_t>(targetSize)));
  if (file_buffer == nullptr) {
    std::cerr << "Error allocating " << targetSize << " bytes for exe buffer.\n";
    close(fd);
    return 1;
  }

  uint64_t totalRead = 0;
  while (totalRead < targetSize) {
    ssize_t n = read(fd, file_buffer + totalRead, targetSize - totalRead);
    if (n <= 0) {
      std::cerr << "Error reading exe file (" << std::strerror(errno) << ").\n";
      free(file_buffer);
      close(fd);
      return 1;
    }
    totalRead += static_cast<uint64_t>(n);
  }
  close(fd);

  retval.buffer = file_buffer;
  retval.size = targetSize;
  retval.isMapped = false;

  return 0;
#endif
}

void OtherTools::ReleaseBuffer() {
  if (retval.buffer == nullptr) return;

  if (retval.isMapped) {
#ifdef _WIN32
    UnmapViewOfFile(retval.buffer);
    if (retval.mappingHandle != nullptr) CloseHandle(retval.mappingHandle);
#else
    munmap(retval.buffer, retval.size);
#endif
  }
  else {
    free(retval.buffer);
  }

  retval.buffer = nullptr;
  retval.size = 0;
  retval.isMapped = false;
#ifdef _WIN32
  retval.mappingHandle = nullptr;
#endif
}

OtherTools::~OtherTools()
{
}
