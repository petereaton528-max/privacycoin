#pragma once
#include <csignal>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace pcdev {
inline void interrupt_self() {
#ifdef _WIN32
  // Explicit test-only crash: terminate this process without stack unwinding.
  TerminateProcess(GetCurrentProcess(),137);
#else
  std::raise(SIGKILL);
#endif
}
}
