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
#include "llvm/Support/FileSystem.h"
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

// log function for compile time (of client function)
void log_print(const std::string& str, bool error = false, const std::string& color = "") {
    std::string prefix = Colors::CYAN + "[SENSITAINT]" + Colors::RESET + " ";
    
    if (error) {
        std::cerr << prefix << Colors::RED << str << Colors::RESET << "\n";
    } else if (!color.empty()) {
        std::cout << prefix << color << str << Colors::RESET << "\n";
    } else {
        std::cout << prefix << str << "\n";
    }
}

// Just to log commands for debugging
bool runCommand(const std::string& cmd) {
    log_print("Running command: " + cmd);
    int result = std::system(cmd.c_str());
    return result == 0;
}

// Get or create printf function
llvm::Function* getPrintf(llvm::Module* M, llvm::LLVMContext& Context) {
    if (auto *printfFunc = M->getFunction("printf")) {
        return printfFunc;
    }
    
    // Create printf declaration  
    llvm::Type *charPtrTy = llvm::PointerType::get(Context, 0);
    llvm::Type *intTy = llvm::Type::getInt32Ty(Context);
    llvm::FunctionType *printfType = llvm::FunctionType::get(intTy, {charPtrTy}, true);
    return llvm::Function::Create(printfType, llvm::Function::ExternalLinkage, "printf", M);
}

// Find all sensitive variables
std::vector<SensitiveVar> findSensitiveVars(llvm::Module* M) {
    std::vector<SensitiveVar> vars;
    
    // Check global annotations
    if (auto *globalAnnotations = M->getGlobalVariable("llvm.global.annotations")) {
        if (auto *annotationsArray = llvm::dyn_cast<llvm::ConstantArray>(globalAnnotations->getInitializer())) {
            for (unsigned i = 0; i < annotationsArray->getNumOperands(); ++i) {
                if (auto *annotationStruct = llvm::dyn_cast<llvm::ConstantStruct>(annotationsArray->getOperand(i))) {
                    if (annotationStruct->getNumOperands() >= 2) {
                        std::string annotation = getAnnotationString(annotationStruct->getOperand(1));
                        if (annotation == "sensitive") {
                            if (auto *globalVar = llvm::dyn_cast<llvm::GlobalVariable>(annotationStruct->getOperand(0))) {
                                std::string name = globalVar->hasName() ? globalVar->getName().str() : "<unnamed>";
                                vars.push_back({globalVar, name, nullptr, true});
                                log_print("Found global: " + name, false, Colors::MAGENTA);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Check local annotations
    for (llvm::Function &F : *M) {
        if (F.isDeclaration()) continue;
        
        for (llvm::BasicBlock &BB : F) {
            for (llvm::Instruction &I : BB) {
                if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
                    if (auto *calledFunc = CI->getCalledFunction()) {
                        if (calledFunc->getName().starts_with("llvm.var.annotation") && CI->getNumOperands() >= 2) {
                            std::string annotation = getAnnotationString(CI->getOperand(1));
                            if (annotation == "sensitive") {
                                llvm::Value *var = CI->getOperand(0);
                                std::string name = var->hasName() ? var->getName().str() : "<unnamed>";
                                vars.push_back({var, name, CI, false});
                                log_print("Found local: " + name + " in " + F.getName().str(), false, Colors::MAGENTA);
                            }
                        }
                    }
                }
            }
        }
    }
    
    return vars;
}

// Insert logs for sensitive variables
void instrumentVars(llvm::Module* M, const std::vector<SensitiveVar>& vars, llvm::LLVMContext& Context) {
    if (vars.empty()) {
        log_print("No variables to instrument", true);
        return;
    }
    
    llvm::Function *printfFunc = getPrintf(M, Context);
    
    for (const auto& var : vars) {
        if (var.isGlobal) continue; // Skip globals for now?
        
        if (var.location) {
            llvm::IRBuilder<> builder(Context);
            if (llvm::Instruction *insertPoint = var.location->getNextNode()) {
                builder.SetInsertPoint(insertPoint);
                
                // Get variable address by casting to void*
                llvm::Type *voidPtrTy = llvm::PointerType::get(Context, 0);
                llvm::Value *varAddr = builder.CreateBitCast(var.variable, voidPtrTy, "var_addr");
                
                // Get variable size - determine type and calculate size  
                llvm::Type *varType = var.variable->getType();
                uint64_t typeSize;
                
                // If it's an alloca instruction, get the allocated type
                if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(var.variable)) {
                    varType = AI->getAllocatedType();
                    typeSize = M->getDataLayout().getTypeAllocSize(varType);
                } else if (varType->isPointerTy()) {
                    // For other pointer types, just use pointer size
                    typeSize = M->getDataLayout().getPointerSize();
                } else {
                    // For non-pointer types, get the type size
                    typeSize = M->getDataLayout().getTypeAllocSize(varType);
                }
                llvm::Value *sizeVal = llvm::ConstantInt::get(llvm::Type::getInt64Ty(Context), typeSize);
                
                // Create format string and variable name string
                llvm::Constant *formatStr = builder.CreateGlobalString("[RUNTIME] Tracking '%s' at %p, size: %llu bytes\n");
                llvm::Constant *nameStr = builder.CreateGlobalString(var.name);
                
                // Insert printf call with name, address, and size
                builder.CreateCall(printfFunc, {formatStr, nameStr, varAddr, sizeVal});
                log_print("Instrumented: " + var.name + " (size: " + std::to_string(typeSize) + " bytes)", false, Colors::GREEN);
            }
        }
    }
}

// === PIPELINE FUNCTIONS ===

// Step 1: Generate basic bytecode from source
bool generateBytecode(const std::string& sourceFile, const std::string& bitcodeFile) {
    log_print("[STEP 1] Generating bytecode from source...", false, Colors::BOLD + Colors::BLUE);
    std::string cmd = "clang -O0 -emit-llvm -c " + sourceFile + " -o " + bitcodeFile;
    if (!runCommand(cmd)) {
        log_print("[ERROR] Failed to generate bytecode", true);
        return false;
    }
    log_print("[STEP 1] Successfully generated: " + bitcodeFile, false, Colors::GREEN);
    return true;
}

// Step 2: Parse module and identify all sensitive variables
std::vector<SensitiveVar> identifySensitiveVars(const std::string& bitcodeFile) {
    log_print("[STEP 2] Identifying sensitive variables...", false, Colors::BOLD + Colors::BLUE);

    llvm::LLVMContext Context;
    llvm::SMDiagnostic Err;
    
    std::unique_ptr<llvm::Module> M = parseIRFile(bitcodeFile, Err, Context);
    if (!M) {
        log_print("[ERROR] Failed to parse bitcode file", true);
        Err.print("sensitaint", llvm::errs());
        return {};
    }
    
    auto vars = findSensitiveVars(M.get());
    log_print("[STEP 2] Found " + std::to_string(vars.size()) + " sensitive variables:", false, Colors::GREEN);
    for (const auto& var : vars) {
        log_print("  - " + var.name + " (" + (var.isGlobal ? "global" : "local") + ")");
    }
    
    return vars;
}

// Step 3: Inject instrumentation for sensitive variables
bool injectInstrumentation(const std::string& inputFile, const std::string& outputFile) {
    log_print("[STEP 3] Injecting instrumentation...", false, Colors::BOLD + Colors::BLUE);

    LLVMContext Context;
    SMDiagnostic Err;
    
    std::unique_ptr<Module> M = parseIRFile(inputFile, Err, Context);
    if (!M) {
        log_print("[ERROR] Failed to parse bitcode for instrumentation", true);
        Err.print("sensitaint", errs());
        return false;
    }
    
    // Find and instrument variables in the same context
    auto vars = findSensitiveVars(M.get());
    instrumentVars(M.get(), vars, Context);
    
    // Write the modified bytecode
    std::error_code EC;
    raw_fd_ostream out(outputFile, EC, sys::fs::OpenFlags::OF_None);
    if (EC) {
        log_print("[ERROR] Failed to write instrumented bytecode: " + EC.message(), true);
        return false;
    }
    
    WriteBitcodeToFile(*M, out);
    log_print("[STEP 3] Successfully instrumented and wrote: " + outputFile, false, Colors::GREEN);
    return true;
}

// Step 4: Build final executable
bool buildExecutable(const std::string& bitcodeFile, const std::string& executableFile) {
    log_print("[STEP 4] Building final executable...", false, Colors::BOLD + Colors::BLUE);
    std::string cmd = "clang " + bitcodeFile + " -o " + executableFile;
    if (!runCommand(cmd)) {
        log_print("[ERROR] Failed to build executable", true);
        return false;
    }
    log_print("[STEP 4] Successfully built executable: " + executableFile, false, Colors::GREEN);
    return true;
}

// Step 5: Clean up temporary files
void cleanupTempFiles(const std::vector<std::string>& tempFiles) {
    log_print("[STEP 5] Cleaning up temporary files...", false, Colors::BOLD + Colors::BLUE);
    for (const auto& file : tempFiles) {
        std::string cmd = "rm -f " + file;
        runCommand(cmd);
        log_print("  - Removed: " + file);
    }
    log_print("[STEP 5] Cleanup complete");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        log_print("Usage: " + std::string(argv[0]) + " <source_file> <output_executable>", true);
        return 1;
    }

    std::string sourceFile = argv[1];
    std::string execFile = argv[2];
    std::string tempBitcode = "temp.bc";
    std::string modifiedBitcode = "modified.bc";

    log_print("=== SensiTaint Instrumentation Pipeline ===", false, Colors::BOLD + Colors::CYAN);
    log_print("Source: " + sourceFile + " -> Executable: " + execFile);

    // Step 1: Generate basic bytecode
    if (!generateBytecode(sourceFile, tempBitcode)) {
        return 1;
    }
    log_print("");
    
    // Step 2: Identify sensitive variables
    std::vector<SensitiveVar> vars = identifySensitiveVars(tempBitcode);
    if (vars.empty()) {
        log_print("[WARNING] No sensitive variables found to instrument");
    }
    log_print("");

    // Step 3: Inject instrumentation
    if (!injectInstrumentation(tempBitcode, modifiedBitcode)) {
        return 1;
    }
    log_print("");
    
    // Step 4: Build final executable
    if (!buildExecutable(modifiedBitcode, execFile)) {
        return 1;
    }
    log_print("");
    
    // Step 5: Clean up temporary files
    cleanupTempFiles({tempBitcode, modifiedBitcode});

    log_print("\n=== Pipeline Complete ===", false, Colors::BOLD + Colors::GREEN);
    log_print("Instrumented executable created: " + execFile);
    log_print("Found and instrumented " + std::to_string(vars.size()) + " sensitive variables");
    return 0;
}
