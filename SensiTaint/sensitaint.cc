#include "sensitaint.hh"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_code>\n";
        return 1;
    }

    std::string sourceFile = argv[1];

    std::string outputFile = sourceFile + ".bc";
    std::string cmd = "clang -O0 -emit-llvm -c " + sourceFile + " -o " + outputFile;

    std::cout << "Running: " << cmd << "\n";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        FATAL("Compilation failed with return code %d", ret);
    }

    std::cout << "Compilation succeeded, output: " << outputFile << "\n";
    return 0;
}
