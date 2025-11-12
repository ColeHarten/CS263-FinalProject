#include "sensitaint.hh"
#include "utils.hh"

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
std::string get_annotation_string(Value* ptr) {
    if (auto *gv = dyn_cast<GlobalVariable>(ptr)) {
        if (auto *init = gv->getInitializer()) {
            if (auto *arr = dyn_cast<ConstantDataArray>(init)) {
                return arr->getAsCString().str();
            }
        }
    }
    // Try indirect access
    if (auto *gep = dyn_cast<GetElementPtrInst>(ptr)) {
        return get_annotation_string(gep->getPointerOperand());
    }
    return "";
}

// Get or create printf function
llvm::Function* get_printf(llvm::Module* m, llvm::LLVMContext& context) {
    if (auto *printf_func = m->getFunction("printf")) {
        return printf_func;
    }
    
    // Create printf declaration  
    llvm::Type *char_ptr_ty = llvm::PointerType::get(context, 0);
    llvm::Type *int_ty = llvm::Type::getInt32Ty(context);
    llvm::FunctionType *printf_type = llvm::FunctionType::get(int_ty, {char_ptr_ty}, true);
    return llvm::Function::Create(printf_type, llvm::Function::ExternalLinkage, "printf", m);
}

// Find all sensitive variables
std::vector<SensitiveVar> find_sensitive_vars(llvm::Module* m) {
    std::vector<SensitiveVar> vars;
    
    // Check global annotations
    if (auto *global_annotations = m->getGlobalVariable("llvm.global.annotations")) {
        if (auto *annotations_array = llvm::dyn_cast<llvm::ConstantArray>(global_annotations->getInitializer())) {
            for (unsigned i = 0; i < annotations_array->getNumOperands(); ++i) {
                if (auto *annotation_struct = llvm::dyn_cast<llvm::ConstantStruct>(annotations_array->getOperand(i))) {
                    if (annotation_struct->getNumOperands() >= 2) {
                        std::string annotation = get_annotation_string(annotation_struct->getOperand(1));
                        if (annotation == "sensitive") {
                            if (auto *global_var = llvm::dyn_cast<llvm::GlobalVariable>(annotation_struct->getOperand(0))) {
                                std::string name = global_var->hasName() ? global_var->getName().str() : "<unnamed>";
                                vars.push_back({global_var, name, nullptr, true});
                                log_print("Found global: " + name, false, Colors::MAGENTA);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Check local annotations
    for (llvm::Function &f : *m) {
        if (f.isDeclaration()) continue;
        
        for (llvm::BasicBlock &bb : f) {
            for (llvm::Instruction &i : bb) {
                if (auto *ci = llvm::dyn_cast<llvm::CallInst>(&i)) {
                    if (auto *called_func = ci->getCalledFunction()) {
                        if (called_func->getName().starts_with("llvm.var.annotation") && ci->getNumOperands() >= 2) {
                            std::string annotation = get_annotation_string(ci->getOperand(1));
                            if (annotation == "sensitive") {
                                llvm::Value *var = ci->getOperand(0);
                                std::string name = var->hasName() ? var->getName().str() : "<unnamed>";
                                vars.push_back({var, name, ci, false});
                                log_print("Found local: " + name + " in " + f.getName().str(), false, Colors::MAGENTA);
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
void instrument_vars(llvm::Module* m, const std::vector<SensitiveVar>& vars, llvm::LLVMContext& context) {
    if (vars.empty()) {
        log_print("No variables to instrument", true);
        return;
    }
    
    llvm::Function *printf_func = get_printf(m, context);
    
    for (const auto& var : vars) {
        if (var.isGlobal) continue;
        
        if (var.location) {
            llvm::IRBuilder<> builder(context);
            if (llvm::Instruction *insert_point = var.location->getNextNode()) {
                builder.SetInsertPoint(insert_point);
                
                llvm::Type *void_ptr_ty = llvm::PointerType::get(context, 0);
                llvm::Value *var_addr = builder.CreateBitCast(var.variable, void_ptr_ty, "var_addr");
                
                llvm::Type *var_type = var.variable->getType();
                uint64_t type_size;
                
                if (auto *ai = llvm::dyn_cast<llvm::AllocaInst>(var.variable)) {
                    var_type = ai->getAllocatedType();
                    type_size = m->getDataLayout().getTypeAllocSize(var_type);
                } else if (var_type->isPointerTy()) {
                    type_size = m->getDataLayout().getPointerSize();
                } else {
                    type_size = m->getDataLayout().getTypeAllocSize(var_type);
                }
                llvm::Value *size_val = llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), type_size);
                
                llvm::Constant *format_str = builder.CreateGlobalString("[RUNTIME] Tracking '%s' at %p, size: %llu bytes\n");
                llvm::Constant *name_str = builder.CreateGlobalString(var.name);
                
                builder.CreateCall(printf_func, {format_str, name_str, var_addr, size_val});
                log_print("Instrumented: " + var.name + " (size: " + std::to_string(type_size) + " bytes)", false, Colors::GREEN);
            }
        }
    }
}



// === PIPELINE FUNCTIONS ===

// Step 1: Generate basic bytecode from source
bool generate_bytecode(const std::string& source_file, const std::string& bitcode_file) {
    log_print("[STEP 1] Generating bytecode from source...", false, Colors::BOLD + Colors::BLUE);
    std::string cmd = "clang -O0 -emit-llvm -c " + source_file + " -o " + bitcode_file;
    if (!run_command(cmd)) {
        log_print("[ERROR] Failed to generate bytecode", true);
        return false;
    }
    log_print("[STEP 1] Successfully generated: " + bitcode_file, false, Colors::GREEN);
    return true;
}

// Step 2: Parse module and identify all sensitive variables
std::vector<SensitiveVar> identify_sensitive_vars(const std::string& bitcode_file, std::shared_ptr<llvm::Module>& m, llvm::LLVMContext& context, llvm::SMDiagnostic& err) {
    log_print("[STEP 2] Identifying sensitive variables...", false, Colors::BOLD + Colors::BLUE);

    // parse the file
    m = llvm::parseIRFile(bitcode_file, err, context);
    if (!m) {
        log_print("[ERROR] Failed to parse bitcode for instrumentation", true);
        err.print("sensitaint", errs());
        return {};
    } else {
        log_print("[STEP 2] Successfully parsed bitcode: " + bitcode_file, false, Colors::GREEN);
    }
    
    auto vars = find_sensitive_vars(m.get());
    log_print("[STEP 2] Found " + std::to_string(vars.size()) + " sensitive variables:", false, Colors::GREEN);
    for (const auto& var : vars) {
        log_print("  - " + var.name + " (" + (var.isGlobal ? "global" : "local") + ")");
    }
    
    return vars;
}

// Step 3: Inject instrumentation for sensitive variables
bool inject_instrumentation(const std::string& input_file, const std::string& output_file, std::vector<SensitiveVar> vars, std::shared_ptr<llvm::Module> m, llvm::LLVMContext& context, llvm::SMDiagnostic& err) {
    log_print("[STEP 3] Injecting instrumentation...", false, Colors::BOLD + Colors::BLUE);
    
    // auto vars = find_sensitive_vars(m.get());
    instrument_vars(m.get(), vars, context);
    
    std::error_code ec;
    raw_fd_ostream out(output_file, ec, sys::fs::OpenFlags::OF_None);
    if (ec) {
        log_print("[ERROR] Failed to write instrumented bytecode: " + ec.message(), true);
        return false;
    }
    
    WriteBitcodeToFile(*m, out);
    log_print("[STEP 3] Successfully instrumented and wrote: " + output_file, false, Colors::GREEN);
    return true;
}

// Step 4: Build final executable
bool build_executable(const std::string& bitcode_file, const std::string& executable_file) {
    log_print("[STEP 4] Building final executable...", false, Colors::BOLD + Colors::BLUE);
    std::string cmd = "clang " + bitcode_file + " -o " + executable_file;
    if (!run_command(cmd)) {
        log_print("[ERROR] Failed to build executable", true);
        return false;
    }
    log_print("[STEP 4] Successfully built executable: " + executable_file, false, Colors::GREEN);
    return true;
}

// Step 5: Clean up temporary files
void cleanup_temp_files(const std::vector<std::string>& temp_files) {
    log_print("[STEP 5] Cleaning up temporary files...", false, Colors::BOLD + Colors::BLUE);
    for (const auto& file : temp_files) {
        std::string cmd = "rm -f " + file;
        run_command(cmd);
        log_print("  - Removed: " + file);
    }
    log_print("[STEP 5] Cleanup complete");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        log_print("Usage: " + std::string(argv[0]) + " <source_file> <output_executable>", true);
        return 1;
    }


    std::string source_file = argv[1];
    std::string exec_file = argv[2];
    std::string temp_bitcode = "temp.bc";
    std::string modified_bitcode = "modified.bc";

    log_print("=== SensiTaint Instrumentation Pipeline ===", false, Colors::BOLD + Colors::CYAN);
    log_print("Source: " + source_file + " -> Executable: " + exec_file);

    // 1: Generate bytecode
    if (!generate_bytecode(source_file, temp_bitcode)) {
        return 1;
    }
    log_print("");

    // 2: Parse module and identify all sensitive variables
    static LLVMContext context;
    static SMDiagnostic err;
    
    std::shared_ptr<Module> m;
    
    std::vector<SensitiveVar> vars = identify_sensitive_vars(temp_bitcode, m, context, err);
    if (vars.empty()) {
        log_print("[WARNING] No sensitive variables found to instrument");
    }
    log_print("");

    // 3: Inject instrumentation
    if (!inject_instrumentation(temp_bitcode, modified_bitcode, vars, m, context, err)) {
        return 1;
    }
    log_print("");
    
    // 4: Build final executable
    if (!build_executable(modified_bitcode, exec_file)) {
        return 1;
    }
    log_print("");

    // 5: Clean up temporary files
    cleanup_temp_files({temp_bitcode, modified_bitcode});

    log_print("\n=== Pipeline Complete ===", false, Colors::BOLD + Colors::GREEN);
    log_print("Instrumented executable created: " + exec_file);
    log_print("Found and instrumented " + std::to_string(vars.size()) + " sensitive variables");
    return 0;
}
