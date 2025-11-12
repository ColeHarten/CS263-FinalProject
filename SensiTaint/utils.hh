#ifndef SENSITAINT_UTILS_HH
#define SENSITAINT_UTILS_HH

#include <string>

// ANSI color codes
namespace Colors {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BOLD = "\033[1m";
}

// Log function for compile time (of client function)
void log_print(const std::string& str, bool error = false, const std::string& color = "");

// Just to log commands for debugging
bool run_command(const std::string& cmd);

#endif // SENSITAINT_UTILS_HH