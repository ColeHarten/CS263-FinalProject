#ifndef SENSITAINT_HH
#define SENSITAINT_HH
#include <stdio.h>
#include <string>
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Instruction.h"


// Struct for tracking sensitive variables
struct SensitiveVar {
    llvm::Value* variable;
    std::string name;
    llvm::Instruction* location;
    bool derived = false;  // true if this variable was found through taint propagation
};

#endif

