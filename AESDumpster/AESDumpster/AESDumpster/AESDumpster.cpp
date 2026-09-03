// AESDumpster 1.2.5 by GHFear

#include "../OtherTools/OtherTools.h"
#include "../KeyTools/KeyDumpster.h"
#include <filesystem>
#include <vector>
#include <iostream>

// Buffer one exe, scan it for keys, print the results. Shared by the debug
// and release entry points below.
static void ProcessFile(OtherTools& other_tools, const std::filesystem::path& filepath) {
  other_tools.PrintFileName(filepath);

  if (other_tools.CreateExeBuffer(filepath) != 0 || other_tools.retval.buffer == nullptr) {
    std::cout << "Skipping this file due to the error above.\n\n";
    return;
  }

  KeyDumpster key_dumpster;
  if (!key_dumpster.FindAESKeys(other_tools.retval.buffer, other_tools.retval.size))
    printf("There were no keys to be found or a problem occurred.\n");
  else
    key_dumpster.PrintKeyInformation();

  other_tools.ReleaseBuffer();
}

// Debug main logic
static void debugmain()
{
  // Debug exe path (set your own path to an exe on your disk here or this won't work)
#ifdef _WIN32
  std::filesystem::path exe_path = LR"(Z:\Exes\NotProtected\SessionGame-Win64-Shipping.exe)";
#else
  std::filesystem::path exe_path = "/path/to/SessionGame-Win64-Shipping.exe";
#endif

  OtherTools other_tools;
  ProcessFile(other_tools, exe_path);
  other_tools.PrintOutro();
}

// Release main logic
static void releasemain(const std::vector<std::filesystem::path>& files)
{
  OtherTools other_tools;

  // Print intro.
  other_tools.PrintIntro();

  if (files.empty()) {
    // Print instructions if launched without arguments.
    other_tools.PrintInstructions();
    return;
  }

  // Main loop. A bad file shouldn't abort the rest of a batch.
  for (const auto& file : files) {
    ProcessFile(other_tools, file);
  }

  // Print outro before exiting.
  other_tools.PrintOutro();
}

// Entrypoint
#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
  std::vector<std::filesystem::path> files;
  for (int i = 1; i < argc; i++) {
    files.emplace_back(argv[i]);
  }

#if defined _DEBUG
  debugmain();
#else
  releasemain(files);
#endif

  std::cin.ignore();
  return 0;
}
