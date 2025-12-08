#include "sensitaint.hh"
#include "utils.hh"

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>
#include <system_error>

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Module.h" 
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IRReader/IRReader.h"

// #include "phasar/DataFlow.h"               
// #include "phasar/PhasarLLVM.h"
// #include "phasar/DataFlow/IfdsIde/IFDSTabulationProblem.h"
// #include "phasar/DataFlow/IfdsIde/FlowFunctions.h"


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
    // Handle direct global variable reference
    if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
        if (gv->hasInitializer()) {
            if (auto *arr = llvm::dyn_cast<llvm::ConstantDataArray>(gv->getInitializer())) {
                return arr->getAsCString().str();
            }
        }
    }
    
    // Handle getelementptr constant expression (most common case for annotations)
    if (auto *ce = llvm::dyn_cast<llvm::ConstantExpr>(ptr)) {
        if (ce->getOpcode() == llvm::Instruction::GetElementPtr) {
            return get_annotation_string(ce->getOperand(0));
        }
    }
    
    // Handle getelementptr instruction
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
    llvm::Type *char_ptr_ty = llvm::PointerType::get(llvm::Type::getInt8Ty(ctx), 0);  // const char* name
    llvm::Type *void_ptr_ty = llvm::PointerType::get(llvm::Type::getInt8Ty(ctx), 0);  // void* ptr
    llvm::Type *size_ty = llvm::Type::getInt64Ty(ctx);         // size_t sz
    llvm::FunctionType *fn_ty = llvm::FunctionType::get(void_ty, {char_ptr_ty, void_ptr_ty, size_ty}, false);
    
    return llvm::Function::Create(fn_ty, llvm::Function::ExternalLinkage, "record_sensitive_var", m.get());
}


// Find all sensitive variables
std::vector<SensitiveVar> find_sensitive_vars(std::shared_ptr<llvm::Module> m) {
    std::vector<SensitiveVar> vars;
    
    // Check local annotations
    for (llvm::Function &f : *m) {
        if (f.isDeclaration()) continue;
        
        for (llvm::BasicBlock &bb : f) {
            for (llvm::Instruction &i : bb) {
                if (auto *ci = llvm::dyn_cast<llvm::CallInst>(&i)) {
                    if (auto *called_func = ci->getCalledFunction()) {
                        if (called_func->getName().startswith("llvm.var.annotation") && ci->getNumOperands() >= 2) {
                            std::string annotation = get_annotation_string(ci->getOperand(1));
                            if (annotation == "sensitive") {
                                
                                llvm::Value *var = ci->getOperand(0);
                                std::string name = var->hasName() ? var->getName().str() : "<local>";
                                
                                // Debug: What type is this variable?
                                log_print("DEBUG: Found sensitive annotation for '" + name + "'");
                                if (auto *inst = llvm::dyn_cast<llvm::Instruction>(var)) {
                                    log_print("DEBUG: Variable is instruction: " + std::string(inst->getOpcodeName()));
                                } else if (auto *arg = llvm::dyn_cast<llvm::Argument>(var)) {
                                    (void)arg;  // Suppress unused variable warning
                                    log_print("DEBUG: Variable is function argument");
                                } else {
                                    log_print("DEBUG: Variable is some other type");
                                }
                                
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
        if (!v.location) 
            continue;

        llvm::IRBuilder<> B(v.location->getNextNode());
        llvm::Value *ptr = v.variable;

        // Debug: Print the actual type of ptr to understand what we're dealing with
        log_print("DEBUG: Variable '" + v.name + "' has type: " + std::string(ptr->getValueName() ? ptr->getValueName()->getKey().str() : "unnamed"));
        if (auto *inst = llvm::dyn_cast<llvm::Instruction>(ptr)) {
            log_print("DEBUG: Instruction opcode: " + std::to_string(inst->getOpcode()));
        }
        
        // Handle bitcast instructions that wrap allocas
        llvm::Value *actualPtr = ptr;
        if (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(ptr)) {
            log_print("DEBUG: Found bitcast, looking for underlying alloca");
            actualPtr = bc->getOperand(0);
        }
        
        if (auto *ai = llvm::dyn_cast<llvm::AllocaInst>(actualPtr)) {
            log_print("DEBUG: Successfully cast to AllocaInst (possibly through bitcast)");
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
                                    mallocCall, llvm::PointerType::get(llvm::Type::getInt8Ty(Ctx), 0)
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
                    ai, llvm::PointerType::get(llvm::Type::getInt8Ty(Ctx), 0)
                );
                llvm::Value *sizeVal = llvm::ConstantInt::get(
                    llvm::Type::getInt64Ty(Ctx), size
                );
                llvm::Value *nameStr = B.CreateGlobalStringPtr(v.name);

                B.CreateCall(record, {nameStr, addr, sizeVal});
                
                log_print("- Instrumented stack allocation");
            }
            continue;
        }
        
        // If we get here, the cast to AllocaInst failed
        log_print("DEBUG: Failed to cast '" + v.name + "' to AllocaInst");
        
        // Let's try to understand what type this actually is
        if (auto *inst = llvm::dyn_cast<llvm::Instruction>(ptr)) {
            log_print("DEBUG: This is an instruction with opcode: " + std::to_string(inst->getOpcode()));
            log_print("DEBUG: Instruction name: " + std::string(inst->getOpcodeName()));
        } else if (auto *arg = llvm::dyn_cast<llvm::Argument>(ptr)) {
            (void)arg;  // Suppress unused variable warning
            log_print("DEBUG: This is a function argument");
        } else if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
            (void)gv;  // Suppress unused variable warning
            log_print("DEBUG: This is a global variable");
        } else if (auto *constant = llvm::dyn_cast<llvm::Constant>(ptr)) {
            (void)constant;  // Suppress unused variable warning
            log_print("DEBUG: This is a constant");
        } else {
            log_print("DEBUG: Unknown value type");
        }
        
        abort();

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
// 5-step pipeline:
//      1) Generate basic bytecode from source
//      2) Parse module and identify all sensitive variables
//      3) Inject instructions for sensitive variables
//      4) Build final executable
//      5) Clean up temporary files

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
        log_print("  - " + var.name + " (local)");
    }
    
    return vars;
}

// Step 3: Inject instructions for sensitive variables
bool inject_instructions(const std::string& input_file, const std::string& output_file, std::vector<SensitiveVar> vars, std::shared_ptr<llvm::Module> m) {
    log_print("[STEP 3] Injecting instructions...", false, Colors::BOLD + Colors::BLUE);
    
    instrument_vars(m, vars);
    
    std::error_code ec;
    llvm::raw_fd_ostream out(output_file, ec, llvm::sys::fs::F_None);
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