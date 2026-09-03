#pragma once
// Cross-platform console color: Windows console attributes on _WIN32, ANSI
// SGR escape codes everywhere else. Header-only so no new source file needs
// wiring into the .vcxproj.
#include <cstdio>

#ifdef _WIN32
#include <Windows.h>
#endif

enum class ConsoleColor { Default, Red, Brown, Yellow, Green };

inline void SetConsoleColor(ConsoleColor color) {
#ifdef _WIN32
  WORD attr = 15;
  switch (color) {
    case ConsoleColor::Red:    attr = 12; break;
    case ConsoleColor::Brown:  attr = 6;  break;
    case ConsoleColor::Yellow: attr = 14; break;
    case ConsoleColor::Green:  attr = 10; break;
    default:                   attr = 15; break;
  }
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
#else
  const char* code = "\033[0m";
  switch (color) {
    case ConsoleColor::Red:    code = "\033[91m"; break;
    case ConsoleColor::Brown:  code = "\033[33m"; break;
    case ConsoleColor::Yellow: code = "\033[93m"; break;
    case ConsoleColor::Green:  code = "\033[92m"; break;
    default:                   code = "\033[0m"; break;
  }
  std::fputs(code, stdout);
#endif
}
