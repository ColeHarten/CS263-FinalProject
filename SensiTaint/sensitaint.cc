#include "sensitaint.hh"
#include "utils.hh"

#include <iostream>
#include <fstream>
#include <regex>
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
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IRReader/IRReader.h"

#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/Pointer/LLVMAliasSet.h"
#include "phasar/PhasarLLVM/TypeHierarchy/DIBasedTypeHierarchy.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/Problems/IFDSTaintAnalysis.h"
#include "phasar/DataFlow/IfdsIde/Solver/IFDSSolver.h"
#include "phasar/PhasarLLVM/TaintConfig/LLVMTaintConfig.h"
#include "phasar/PhasarLLVM/TaintConfig/TaintConfigData.h"
#include "phasar/PhasarLLVM/TaintConfig/TaintConfigBase.h"
#include "phasar/PhasarLLVM/HelperAnalyses.h"
#include "phasar/ControlFlow/CallGraphAnalysisType.h"
#include <set>
#include <map>

/*
*   This is the program to take in the client C program, inject code to record sensitive
*   variables at runtime in a shadow buffer, install signal handlers to santize the core 
*   dump and then generate an executable file. 
*
*   There is a lot of really nasty parsing logic here. 
*   Here is the docs for the LLVM parser: https://llvm.org/docs/GettingStarted.html
*/

// Extract annotation string from LLVM value
std::string get_annotation_string(llvm::Value* ptr) {
    if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
        if (auto *init = gv->getInitializer()) {
            if (auto *arr = llvm::dyn_cast<llvm::ConstantDataArray>(init)) {
                return arr->getAsCString().str();
            }
        }
    }
    // Try indirect access
    if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(ptr)) {
        return get_annotation_string(gep->getPointerOperand());
    }
    return "";
}

// Get the record_sensitive_var function, or declare it if not present
llvm::Function* get_record_sensitive_var(std::shared_ptr<llvm::Module> m) {
    if (auto *f = m->getFunction("record_sensitive_var"))
        return f;
    
    llvm::LLVMContext &ctx = m->getContext();
    llvm::Type *void_ty = llvm::Type::getVoidTy(ctx);
    llvm::Type *char_ptr_ty = llvm::PointerType::get(ctx, 0);  // const char* name
    llvm::Type *void_ptr_ty = llvm::PointerType::get(ctx, 0);  // void* ptr
    llvm::Type *size_ty = llvm::Type::getInt64Ty(ctx);         // size_t sz
    llvm::FunctionType *fn_ty = llvm::FunctionType::get(void_ty, {char_ptr_ty, void_ptr_ty, size_ty}, false);
    
    return llvm::Function::Create(fn_ty, llvm::Function::ExternalLinkage, "record_sensitive_var", m.get());
}

// Find all sensitive variables
std::vector<SensitiveVar> find_sensitive_vars(std::shared_ptr<llvm::Module> m) {
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
                                std::string name = global_var->hasName() ? global_var->getName().str() : "<local>";
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
                                std::string name = var->hasName() ? var->getName().str() : "<local>";
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

// Helper function to find malloc calls that store into a given pointer
std::vector<llvm::CallInst*> find_malloc_stores(llvm::Value* ptr) {
    std::vector<llvm::CallInst*> mallocCalls;
    
    // Look for stores into this pointer
    for (auto *user : ptr->users()) {
        if (auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (store->getPointerOperand() == ptr) {
                llvm::Value *storedVal = store->getValueOperand();
                
                // Check if stored value is a malloc call
                if (auto *call = llvm::dyn_cast<llvm::CallInst>(storedVal)) {
                    if (auto *callee = call->getCalledFunction()) {
                        if (callee->getName() == "malloc" || callee->getName() == "calloc" || 
                            callee->getName() == "realloc") {
                            mallocCalls.push_back(call);
                        }
                    }
                }
            }
        }
    }
    
    return mallocCalls;
}

void instrument_vars(std::shared_ptr<llvm::Module> m, const std::vector<SensitiveVar>& vars) {
    llvm::Module &M = *m;
    llvm::LLVMContext &Ctx = M.getContext();
    const llvm::DataLayout &DL = M.getDataLayout();

    llvm::Function *record = get_record_sensitive_var(m);

    for (const auto &v : vars) {
        if (v.isGlobal || !v.location) 
            continue;

        llvm::IRBuilder<> B(v.location->getNextNode());
        llvm::Value *ptr = v.variable;

        if (auto *ai = llvm::dyn_cast<llvm::AllocaInst>(ptr)) {
            // Get the allocated type, not the pointer type
            llvm::Type *allocatedType = ai->getAllocatedType();
            
            // Check if this is a pointer type that might point to heap memory
            if (allocatedType->isPointerTy()) {
                auto mallocCalls = find_malloc_stores(ptr);
                
                bool instrumentedHeap = false;
                for (auto *mallocCall : mallocCalls) {
                    // Find the store instruction that stores this malloc result
                    for (auto *user : mallocCall->users()) {
                        if (auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
                            if (store->getPointerOperand() == ptr) {
                                // Instrument the heap allocation
                                llvm::IRBuilder<> heapB(store->getNextNode());
                                
                                llvm::Value *heapAddr = heapB.CreateBitCast(
                                    mallocCall, llvm::PointerType::get(Ctx, 0)
                                );
                                
                                llvm::Value *heapSize;
                                if (mallocCall->getCalledFunction()->getName() == "calloc") {
                                    // calloc(num, size) - multiply arguments
                                    llvm::Value *num = mallocCall->getArgOperand(0);
                                    llvm::Value *size = mallocCall->getArgOperand(1);
                                    heapSize = heapB.CreateMul(num, size);
                                } else {
                                    // Default to using first argument
                                    heapSize = mallocCall->getArgOperand(0);
                                }
                                
                                llvm::Value *heapNameStr = heapB.CreateGlobalStringPtr(v.name + "_heap");
                                heapB.CreateCall(record, {heapNameStr, heapAddr, heapSize});
                                
                                instrumentedHeap = true;
                                log_print("- Instrumented heap allocation");
                                break;
                            }
                        }
                    }
                }
                
                if (!instrumentedHeap) {
                    log_print("[WARN] No heap allocation found for pointer: " + v.name);
                }
            } else {
                // Regular stack variable (not a pointer)
                uint64_t size = DL.getTypeAllocSize(allocatedType);

                llvm::Value *addr = B.CreateBitCast(
                    ai, llvm::PointerType::get(Ctx, 0)
                );
                llvm::Value *sizeVal = llvm::ConstantInt::get(
                    llvm::Type::getInt64Ty(Ctx), size
                );
                llvm::Value *nameStr = B.CreateGlobalStringPtr(v.name);

                B.CreateCall(record, {nameStr, addr, sizeVal});
                
                log_print("- Instrumented stack allocation");
            }
            continue;
        } else {
            assert(false);
        }

        /*
        *   HERE IS MAYBE WHERE WE SHOULD HANDLE NON-ALLOCATION TAINT PROPOGATION SOMEHOW
        *   IT MAY ALSO BE BE BETTER TO DO THIS IN THE `find_sensitive_vars` FUNCTION
        */
        
        // If no specific case matched, log the error
        log_print("[ERROR]: Could not instrument variable " + v.name + " - unsupported pattern", true);
    }
}

// === PIPELINE FUNCTIONS ===
// These are the functions that run the program. I tried to break it up into a clean-ish
// 6-step pipeline:
//      1) Transform sensitive keyword into annotations
//      2) Generate basic bytecode from source
//      3) Parse module and identify all sensitive variables
//      4) Inject instructions for sensitive variables
//      5) Build final executable
//      6) Clean up temporary files

// Step 1: Transform sensitive keyword into annotations for phasar
bool preprocess_source(const std::string& source_file, std::string& preprocessed_file) {
    log_print("[STEP 1] Transforming sensitive keyword to annotations...", false, Colors::BOLD + Colors::BLUE);
    
    std::ifstream infile(source_file);
    if (!infile.is_open()) {
        log_print("[ERROR] Failed to open source file: " + source_file, true);
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    infile.close();
    
    // regex for 'sensitive <type>' -> '<type> __attribute__((annotate("sensitive")))'
    // I AI-generated this regex so it might not work in every case, def should revist
    // if we have problems later with injecting annotations
    std::regex sensitive_regex(R"(\bsensitive\s+([a-zA-Z_][a-zA-Z0-9_]*\s*\*?)\s+([a-zA-Z_][a-zA-Z0-9_]*))");
    std::string transformed = std::regex_replace(content, sensitive_regex, 
        R"($1 __attribute__((annotate("sensitive"))) $2)");
    
    size_t count = 0;
    std::sregex_iterator it(content.begin(), content.end(), sensitive_regex);
    std::sregex_iterator end;
    while (it != end) {
        count++;
        ++it;
    }
    
    if (count > 0) {
        log_print("Transformed " + std::to_string(count) + " sensitive keywords into annotations");
        
        preprocessed_file = source_file + ".preprocessed.c";
        std::ofstream outfile(preprocessed_file);
        if (!outfile.is_open()) {
            log_print("[ERROR] Failed to create preprocessed file", true);
            return false;
        }
        outfile << transformed;
        outfile.close();
        
        log_print("[STEP 1] Preprocessed file created: " + preprocessed_file, false, Colors::GREEN);
    } else {
        log_print("No sensitive keywords found, using original file");
        preprocessed_file = source_file;
    }
    
    return true;
}

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
std::vector<SensitiveVar> identify_sensitive_vars(const std::string& bitcode_file, std::shared_ptr<llvm::Module>& m) {
    log_print("[STEP 2] Identifying sensitive variables...", false, Colors::BOLD + Colors::BLUE);

    static llvm::LLVMContext context;
    static llvm::SMDiagnostic err;

    // parse the file
    m = llvm::parseIRFile(bitcode_file, err, context);
    if (!m) {
        log_print("[ERROR] Failed to parse bitcode for instrumentation", true);
        err.print("sensitaint", llvm::errs());
        return {};
    } else {
        log_print("[STEP 2] Successfully parsed bitcode: " + bitcode_file, false, Colors::GREEN);
    }
    
    auto vars = find_sensitive_vars(m);
    log_print("[STEP 2] Found " + std::to_string(vars.size()) + " sensitive variables:", false, Colors::GREEN);
    for (const auto& var : vars) {
        log_print("  - " + var.name + " (" + (var.isGlobal ? "global" : "local") + ")");
    }
    
    return vars;
}

// Step 3: Inject instructions for sensitive variables
bool inject_instructions(const std::string& input_file, const std::string& output_file, std::vector<SensitiveVar> vars, std::shared_ptr<llvm::Module> m) {
    log_print("[STEP 3] Injecting instructions...", false, Colors::BOLD + Colors::BLUE);
    
    instrument_vars(m, vars);
    
    std::error_code ec;
    llvm::raw_fd_ostream out(output_file, ec, llvm::sys::fs::OpenFlags::OF_None);
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

    // Build with no optimization
    std::string cmd = "clang -O0 " + bitcode_file + " runtime/runtime_helpers.c runtime/hashmap.c -o " + executable_file;
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
    std::shared_ptr<llvm::Module> m;
    
    std::vector<SensitiveVar> vars = identify_sensitive_vars(temp_bitcode, m);
    if (vars.empty()) {
        log_print("[WARNING] No sensitive variables found to instrument");
    }
    log_print("");

    // 3: Inject instructions
    if (!inject_instructions(temp_bitcode, modified_bitcode, vars, m)) {
        return 1;
    }
    log_print("");
    
    // 4: Build final executable
    if (!build_executable(modified_bitcode, exec_file)) {
        return 1;
    }
    log_print("");

    // 5: Clean up temporary files (temporarily disabled for debugging)
    cleanup_temp_files({temp_bitcode, modified_bitcode});

    log_print("\n=== Pipeline Complete ===", false, Colors::BOLD + Colors::GREEN);
    log_print("Instrumented executable created: " + exec_file);
    log_print("Found and instrumented " + std::to_string(vars.size()) + " sensitive variables");
    return 0;
}
