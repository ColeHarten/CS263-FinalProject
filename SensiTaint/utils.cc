#include "utils.hh"
#include <iostream>

void log_print(const std::string& str, bool error, const std::string& color) {
    std::string prefix = Colors::CYAN + "[SENSITAINT]" + Colors::RESET + " ";
    
    if (error) {
        std::cerr << prefix << Colors::RED << str << Colors::RESET << "\n";
    } else if (!color.empty()) {
        std::cout << prefix << color << str << Colors::RESET << "\n";
    } else {
        std::cout << prefix << str << "\n";
    }
}

bool run_command(const std::string& cmd) {
    log_print("Running command: " + cmd);
    int result = std::system(cmd.c_str());
    return result == 0;
}