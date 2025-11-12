#include "sensitaint.hh"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>
#include <system_error>

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h" 
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IRReader/IRReader.h"

using namespace llvm;

// Extract annotation string from LLVM value
std::string getAnnotationString(Value* ptr) {
    if (auto *GV = dyn_cast<GlobalVariable>(ptr)) {
        if (auto *init = GV->getInitializer()) {
            if (auto *arr = dyn_cast<ConstantDataArray>(init)) {
                return arr->getAsCString().str();
            }
        }
    }
    // Try indirect access
    if (auto *GEP = dyn_cast<GetElementPtrInst>(ptr)) {
        return getAnnotationString(GEP->getPointerOperand());
    }
    return "";
}

// Find all sensitive variables
std::vector<SensitiveVar> findSensitiveVars(Module* M) {
    std::vector<SensitiveVar> vars;
    
    // Check global annotations
    if (auto *globalAnnotations = M->getGlobalVariable("llvm.global.annotations")) {
        if (auto *annotationsArray = dyn_cast<ConstantArray>(globalAnnotations->getInitializer())) {
            for (unsigned i = 0; i < annotationsArray->getNumOperands(); ++i) {
                if (auto *annotationStruct = dyn_cast<ConstantStruct>(annotationsArray->getOperand(i))) {
                    if (annotationStruct->getNumOperands() >= 2) {
                        std::string annotation = getAnnotationString(annotationStruct->getOperand(1));
                        if (annotation == "sensitive") {
                            if (auto *globalVar = dyn_cast<GlobalVariable>(annotationStruct->getOperand(0))) {
                                std::string name = globalVar->hasName() ? globalVar->getName().str() : "<unnamed>";
                                vars.push_back({globalVar, name, nullptr, true});
                                std::cout << "[SENSITAINT] Found global: " << name << "\n";
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Check local annotations
    for (Function &F : *M) {
        if (F.isDeclaration()) continue;
        
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (auto *calledFunc = CI->getCalledFunction()) {
                        if (calledFunc->getName().starts_with("llvm.var.annotation") && CI->getNumOperands() >= 2) {
                            std::string annotation = getAnnotationString(CI->getOperand(1));
                            if (annotation == "sensitive") {
                                Value *var = CI->getOperand(0);
                                std::string name = var->hasName() ? var->getName().str() : "<unnamed>";
                                vars.push_back({var, name, CI, false});
                                std::cout << "[SENSITAINT] Found local: " << name << " in " << F.getName().str() << "\n";
                            }
                        }
                    }
                }
            }
        }
    }
    
    return vars;
}

// Get or create printf function
Function* getPrintf(Module* M, LLVMContext& Context) {
    if (auto *printfFunc = M->getFunction("printf")) {
        return printfFunc;
    }
    
    // Create printf declaration  
    Type *charPtrTy = PointerType::get(Context, 0);
    Type *intTy = Type::getInt32Ty(Context);
    FunctionType *printfType = FunctionType::get(intTy, {charPtrTy}, true);
    return Function::Create(printfType, Function::ExternalLinkage, "printf", M);
}

// Insert logs for sensitive variables
void instrumentVars(Module* M, const std::vector<SensitiveVar>& vars, LLVMContext& Context) {
    if (vars.empty()) {
        std::cout << "[SENSITAINT] No variables to instrument\n";
        return;
    }
    
    Function *printfFunc = getPrintf(M, Context);
    
    for (const auto& var : vars) {
        if (var.isGlobal) continue; // Skip globals for now?
        
        if (var.location) {
            IRBuilder<> builder(Context);
            if (Instruction *insertPoint = var.location->getNextNode()) {
                builder.SetInsertPoint(insertPoint);
                
                // Get variable address by casting to void*
                Type *voidPtrTy = PointerType::get(Context, 0);
                Value *varAddr = builder.CreateBitCast(var.variable, voidPtrTy, "var_addr");
                
                // Get variable size - determine type and calculate size  
                Type *varType = var.variable->getType();
                uint64_t typeSize;
                
                // If it's an alloca instruction, get the allocated type
                if (auto *AI = dyn_cast<AllocaInst>(var.variable)) {
                    varType = AI->getAllocatedType();
                    typeSize = M->getDataLayout().getTypeAllocSize(varType);
                } else if (varType->isPointerTy()) {
                    // For other pointer types, just use pointer size
                    typeSize = M->getDataLayout().getPointerSize();
                } else {
                    // For non-pointer types, get the type size
                    typeSize = M->getDataLayout().getTypeAllocSize(varType);
                }
                Value *sizeVal = ConstantInt::get(Type::getInt64Ty(Context), typeSize);
                
                // Create format string and variable name string
                Constant *formatStr = builder.CreateGlobalString("[RUNTIME] Tracking '%s' at %p, size: %llu bytes\n");
                Constant *nameStr = builder.CreateGlobalString(var.name);
                
                // Insert printf call with name, address, and size
                builder.CreateCall(printfFunc, {formatStr, nameStr, varAddr, sizeVal});
                std::cout << "[SENSITAINT] Instrumented: " << var.name << " (size: " << typeSize << " bytes)\n";
            }
        }
    }
}

// Process LLVM module
void processModule(const std::string& llvmFile, const std::string& outputFile) {
    LLVMContext Context;
    SMDiagnostic Err;

    // Parse the LLVM IR file
    std::unique_ptr<Module> M = parseIRFile(llvmFile, Err, Context);
    if (!M) {
        std::cerr << "Error parsing IR file\n";
        Err.print("sensitaint", errs());
        return;
    }

    // Find and instrument sensitive variables
    auto vars = findSensitiveVars(M.get());
    instrumentVars(M.get(), vars, Context);

    // Write modified bitcode
    std::error_code EC;
    raw_fd_ostream out(outputFile, EC);
    if (!EC) {
        WriteBitcodeToFile(*M, out);
        std::cout << "[SENSITAINT] Output written to " << outputFile << "\n";
    } else {
        std::cerr << "Error writing output: " << EC.message() << "\n";
    }
}

// Just to log commands for debugging
bool runCommand(const std::string& cmd) {
    std::cout << "Running: " << cmd << "\n";
    int result = std::system(cmd.c_str());
    return result == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <source_file> <output_executable>\n";
        return 1;
    }

    std::string sourceFile = argv[1];
    std::string execFile = argv[2];
    std::string tempBitcode = "temp.bc";
    std::string modifiedBitcode = "modified.bc";

    std::cout << "=== Step 1: Compile to bitcode ===\n";
    if (!runCommand("clang -O0 -emit-llvm -c " + sourceFile + " -o " + tempBitcode)) {
        std::cerr << "Compilation failed\n";
        return 1;
    }
    
    std::cout << "\n=== Step 2: Instrument ===\n";
    processModule(tempBitcode, modifiedBitcode);
    
    std::cout << "\n=== Step 3: Link executable ===\n";
    if (!runCommand("clang " + modifiedBitcode + " -o " + execFile)) {
        std::cerr << "Linking failed\n";
        return 1;
    }
    
    std::cout << "\n=== Step 4: Cleanup intermediate files ===\n";
    // Remove all the intermediate bytecode files
    runCommand("rm -f " + tempBitcode + " " + modifiedBitcode);
    std::cout << "Removed intermediate bytecode files\n";
    
    std::cout << "\n=== Success! ===\n";
    std::cout << "Created executable: " << execFile << "\n";
    return 0;
}
