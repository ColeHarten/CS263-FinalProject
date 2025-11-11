#include "sensitaint.hh"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IRReader/IRReader.h"

/*
    Generally, I am envisioning the system working as follows:
    - There is a source file (test.c)
        - This source file includes the header "sensitive.h," which includes the definition
           of the `sensitive` keyword.
        - The programmer will label variables as `sensitive` in the source file
    - There is also the library file (sensitaint.cc)
        - This file will be compiled completely
        - The user will run `./sensitaint test.c` to pass the source file to this executable
        - This executable will compile the test.c to get the LLVM intermediate representation (IR) file (test.ll)
        - Then, it will pass this IR file to a separate processor that will go through and find the `sensitive` variables
            -> We will use PhASAR to go through and mark all of the secondary sensitive variables as such
        - For each of these, it will insert a call to `register_sensitive` call into the code to track it in some memory
*/

// This is just to test the instruction insertion
void insert_print(std::string llvm_file) {
    llvm::LLVMContext Context;
    llvm::SMDiagnostic Err;

    // Load the bitcode module
    std::unique_ptr<llvm::Module> M = llvm::parseIRFile(llvm_file, Err, Context);
    if (!M) {
        Err.print("sensitaint", llvm::errs());
        return;
    }

    // Pick the first function as an example insertion target
    llvm::Function *F = nullptr;
    for (auto &Func : *M) {
        if (!Func.isDeclaration()) {
            F = &Func;
            break;
        }
    }

    if (!F) {
        std::cerr << "No suitable function found.\n";
        return;
    }

    // Insert code at the top of the first basic block
    llvm::BasicBlock &entry = F->getEntryBlock();
    llvm::IRBuilder<> builder(&*entry.getFirstInsertionPt());

    // Create a printf declaration if it doesn't exist
    llvm::Function *printfFunc = M->getFunction("printf");
    if (!printfFunc) {
        // Create printf function type: int printf(char*, ...)
        llvm::Type *int8Ty = llvm::Type::getInt8Ty(Context);
        llvm::Type *int8PtrTy = llvm::PointerType::get(int8Ty, 0);
        llvm::Type *intTy = llvm::Type::getInt32Ty(Context);
        llvm::FunctionType *printfType = llvm::FunctionType::get(intTy, {int8PtrTy}, true);
        printfFunc = llvm::Function::Create(printfType, llvm::Function::ExternalLinkage, "printf", M.get());
    }

    // Create a global string constant for the message
    llvm::Constant *formatStr = builder.CreateGlobalStringPtr("[SENSITAINT] Instrumentation active in function: %s\n", "sensitaint_msg");
    
    // Get the function name as a string
    llvm::Constant *funcNameStr = builder.CreateGlobalStringPtr(F->getName(), "func_name");

    // Insert the printf call
    builder.CreateCall(printfFunc, {formatStr, funcNameStr});

    // Let's allocate 1024 bytes of "shadow memory" (keeping original functionality)
    llvm::Type *int8Ty = llvm::Type::getInt8Ty(Context);
    llvm::Type *int32Ty = llvm::Type::getInt32Ty(Context);
    llvm::Value *allocSize = llvm::ConstantInt::get(int32Ty, 1024);

    llvm::Value *shadowPtr = builder.CreateAlloca(int8Ty, allocSize, "shadow_buf");

    // Store something in shadow memory and print its address for verification
    builder.CreateStore(llvm::ConstantInt::get(int8Ty, 42), shadowPtr);
    
    // Print the shadow buffer address for verification
    llvm::Constant *addrFormatStr = builder.CreateGlobalStringPtr("[SENSITAINT] Shadow buffer allocated at: %p\n", "addr_msg");
    llvm::Value *ptrAsInt = builder.CreatePtrToInt(shadowPtr, llvm::Type::getInt64Ty(Context));
    builder.CreateCall(printfFunc, {addrFormatStr, ptrAsInt});

    // Write the modified bitcode to a new file in the same directory as the source
    // Extract directory from llvm_file path
    size_t last_slash = llvm_file.find_last_of('/');
    std::string directory = (last_slash != std::string::npos) ? llvm_file.substr(0, last_slash + 1) : "";
    std::string output_path = directory + "modified.bc";
    
    std::error_code EC;
    llvm::raw_fd_ostream out(output_path, EC);
    if (EC) {
        std::cerr << "Error opening output file: " << EC.message() << "\n";
        return;
    }

    llvm::WriteBitcodeToFile(*M, out);
    out.close();
}

void generate_llvm(std::string source_file, std::string output_file) {
    std::string cmd = "clang -O0 -emit-llvm -c -S " + source_file + " -o " + output_file;

    std::cout << "Running: " << cmd << "\n";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        FATAL("Compilation failed with return code %d", ret);
    }

    std::cout << "Compilation succeeded, output: " << output_file << "\n";
}

void compile_bitcode(std::string bitcode_file, std::string output_executable) {
    std::string cmd = "clang " + bitcode_file + " -o " + output_executable;

    std::cout << "Running: " << cmd << "\n";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        FATAL("Compilation of bitcode failed with return code %d", ret);
    }

    std::cout << "Bitcode compilation succeeded, executable: " << output_executable << "\n";
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_code>\n";
        return 1;
    }

    std::string source_file = argv[1];
    std::string llvm_file = source_file.substr(0, source_file.find_last_of('.')) + ".bc";
    std::string executable_file = source_file.substr(0, source_file.find_last_of('.')) + "_modified";
    
    // Get the directory of the source file for modified.bc path
    size_t last_slash = source_file.find_last_of('/');
    std::string directory = (last_slash != std::string::npos) ? source_file.substr(0, last_slash + 1) : "";
    std::string modified_bc_path = directory + "modified.bc";

    generate_llvm(source_file, llvm_file);

    insert_print(llvm_file);
    
    compile_bitcode(modified_bc_path, executable_file);
    
    return 0;
}
