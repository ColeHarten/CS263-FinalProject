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

// taint analysis with phasar
std::vector<SensitiveVar> perform_phasar_taint_analysis(
    const std::string& bitcode_file,
    const std::vector<SensitiveVar>& explicit_vars,
    std::shared_ptr<llvm::Module> original_module) 
{
    std::vector<SensitiveVar> derived_vars;
    
    // allows phasar to track taint sources from functions
    log_print("[PhASAR] Injecting taint markers into bitcode...", false, Colors::BOLD + Colors::CYAN);
    
    // load bitcode to temp module
    llvm::LLVMContext temp_context;
    llvm::SMDiagnostic err;
    auto temp_module = llvm::parseIRFile(bitcode_file, err, temp_context);
    if (!temp_module) {
        log_print("[PhASAR ERROR] Failed to load bitcode for marker injection", true);
        return derived_vars;
    }
    
    // create marker function declaration
    llvm::FunctionType *marker_type = llvm::FunctionType::get(
        llvm::Type::getInt32Ty(temp_context),
        {llvm::Type::getInt32Ty(temp_context)},
        false
    );
    llvm::Function *marker_func = llvm::Function::Create(
        marker_type,
        llvm::Function::ExternalLinkage,
        "__sensitaint_mark_tainted",
        temp_module.get()
    );
    marker_func->setDoesNotThrow();
    marker_func->setWillReturn();
    
    log_print("Created marker function declaration");

    // for each sensitive var inject markers
    int markers_injected = 0;
    for (const auto& explicit_var : explicit_vars) {
        if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(explicit_var.variable)) {
            std::string func_name = AI->getFunction()->getName().str();
            
            // find alloca in temp module
            int target_idx = 0;
            bool found_idx = false;
            for (auto &BB : *AI->getFunction()) {
                for (auto &I : BB) {
                    if (auto *CheckAI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                        if (CheckAI == AI) {
                            found_idx = true;
                            break;
                        }
                        target_idx++;
                    }
                }
                if (found_idx) break;
            }
            
            // find the same alloca in temp_module
            for (auto &F : *temp_module) {
                if (F.getName() != func_name) continue;
                
                int current_idx = 0;
                for (auto &BB : F) {
                    for (auto &I : BB) {
                        if (auto *TempAI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                            if (current_idx == target_idx) {
                                // found the alloca so inject marker call
                                for (auto *User : TempAI->users()) {
                                    if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(User)) {
                                        if (SI->getPointerOperand() == TempAI) {
                                            llvm::IRBuilder<> builder(SI);
                                            llvm::Value *original_value = SI->getValueOperand();
                                            llvm::Value *marked_value = builder.CreateCall(marker_func, {original_value});
                                            SI->setOperand(0, marked_value);
                                            markers_injected++;
                                            log_print("Injected marker for variable " + explicit_var.name);
                                            break;
                                        }
                                    }
                                }
                                goto next_var;
                            }
                            current_idx++;
                        }
                    }
                }
                next_var:
                break;
            }
        }
    }
    
    // now that bitcode is modified, write to a temp file for phasar
    std::string phasar_bc = bitcode_file + ".phasar.bc";
    std::error_code ec;
    llvm::raw_fd_ostream out(phasar_bc, ec, llvm::sys::fs::OpenFlags::OF_None);
    if (ec) {
        log_print("[PhASAR ERROR] Failed to write transformed bitcode: " + ec.message(), true);
        return derived_vars;
    }
    WriteBitcodeToFile(*temp_module, out);
    out.close();
    
    log_print("[PhASAR] Injected " + std::to_string(markers_injected) + " marker calls, saved to " + phasar_bc);

    // Map to track phasar allocas to original module allocas
    std::map<std::pair<std::string, int>, llvm::AllocaInst*> original_allocas_by_position;
    
    for (auto &F : *original_module) {
        int alloca_idx = 0;
        for (auto &BB : F) {
            for (auto &I : BB) {
                if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                    std::string func_name = F.getName().str();
                    original_allocas_by_position[{func_name, alloca_idx}] = AI;
                    alloca_idx++;
                }
            }
        }
    }
    
    log_print("[PhASAR] Starting taint propagation analysis...", false, Colors::BOLD + Colors::CYAN);

    try {
        // set for source vals
        std::set<const llvm::Value*> sourceValues;
        for (const auto& var : explicit_vars) {
            sourceValues.insert(var.variable);
        }
        
        log_print("[PhASAR] Found " + std::to_string(sourceValues.size()) + " taint sources");
        
        std::vector<std::string> entryPoints = {"main"};
        psr::HelperAnalyses HA(phasar_bc, entryPoints);
        
        if (!HA.getProjectIRDB().isValid()) {
            log_print("[PhASAR ERROR] Failed to load IR database", true);
            return derived_vars;
        }
        
        // find the sensitive allocas in phasar module by matching annotations
        // need to do again bc phasar loads a fresh module with different pointers
        log_print("[PhASAR] Re-identifying sensitive allocas in PhASAR's module...");
        std::set<const llvm::Value*> phasar_sensitive_allocas;
        
        auto allFunctions = HA.getProjectIRDB().getAllFunctions();
        
        for (const auto *F : allFunctions) {
            if (!F || F->isDeclaration()) continue;
            
            for (const auto &BB : *F) {
                for (const auto &I : BB) {
                    if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                        // Check if this alloca has a sensitive annotation
                        for (auto *User : AI->users()) {
                            if (auto *Call = llvm::dyn_cast<llvm::CallInst>(User)) {
                                if (auto *CalledFunc = Call->getCalledFunction()) {
                                    if (CalledFunc->getName() == "llvm.var.annotation") {
                                        // Operand 0 is the annotated variable, 1 is ptr to annotation str
                                        if (Call->getNumOperands() >= 2) 
                                            llvm::Value *AnnotationOp = Call->getOperand(1);
                                            llvm::GlobalVariable *GV = nullptr;
                                            if (auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(AnnotationOp)) {
                                                GV = llvm::dyn_cast<llvm::GlobalVariable>(CE->getOperand(0));
                                            } else {
                                                GV = llvm::dyn_cast<llvm::GlobalVariable>(AnnotationOp);
                                            }
                                            
                                            if (GV && GV->hasInitializer()) {
                                                if (auto *CDA = llvm::dyn_cast<llvm::ConstantDataArray>(GV->getInitializer())) {
                                                    llvm::StringRef annotationStr = CDA->getAsString();
                                                    if (annotationStr.startswith("sensitive")) {
                                                        phasar_sensitive_allocas.insert(AI);
                                                        log_print("Re-found sensitive alloca in PhASAR module");
                                                    }
                                                }
                                            }
                                        
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // phasar tracks function sources, so we inject marker function call wrappers
        log_print("[PhASAR] Injecting taint marker function for sensitive variables...");
        
        psr::TaintConfigData config_data;
        psr::FunctionData marker_func;
        marker_func.Name = "__sensitaint_mark_tainted";
        marker_func.ReturnCat = psr::TaintCategory::Source;
        config_data.Functions.push_back(marker_func);
        
        log_print("Registered __sensitaint_mark_tainted as taint source function");
        
        psr::LLVMTaintConfig config(HA.getProjectIRDB(), config_data);
        log_print("[PhASAR] Taint config created with " + std::to_string(config_data.Functions.size()) + " source functions");

        // run the taint analysis solver provided by phasar
        log_print("[PhASAR] Running IFDS solver...");
        psr::IFDSTaintAnalysis TaintProblem(&HA.getProjectIRDB(), &HA.getAliasInfo(), &config, entryPoints, true);
        psr::IFDSSolver Solver(TaintProblem, &HA.getICFG());
        Solver.solve();
        
        log_print("[PhASAR] Solver complete!");
        log_print("[PhASAR] Extracting tainted values...");

        // avoid duplicates
        std::set<const llvm::Value*> seen_values;
        std::set<const llvm::Value*> tainted_allocs;
        int total_facts = 0;
        
        for (const auto *F : HA.getProjectIRDB().getAllFunctions()) {
            if (!F || F->isDeclaration()) continue;
            
            for (const auto &BB : *F) {
                for (const auto &I : BB) {
                    auto Facts = Solver.ifdsResultsAt(&I);
                    
                    if (!Facts.empty()) {
                        total_facts += Facts.size();
                    }
                    
                    for (const auto *Fact : Facts) {
                        if (!Fact || Fact == TaintProblem.getZeroValue()) continue;
                        
                        if (seen_values.count(Fact)) continue;
                        seen_values.insert(Fact);

                        // Check if this is an alloca instruction which would be a stack var
                        if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(Fact)) {
                            if (!tainted_allocs.count(AI)) {
                                tainted_allocs.insert(AI);
                                
                                // Map back to original module by position
                                std::string func_name = AI->getFunction() ? AI->getFunction()->getName().str() : "";
                                
                                int alloca_idx = 0;
                                bool found = false;
                                for (auto &BB : *AI->getFunction()) {
                                    for (auto &I : BB) {
                                        if (auto *CurAI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                                            if (CurAI == AI) {
                                                found = true;
                                                break;
                                            }
                                            alloca_idx++;
                                        }
                                    }
                                    if (found) break;
                                }
                                
                                auto key = std::make_pair(func_name, alloca_idx);
                                if (original_allocas_by_position.count(key)) {
                                    llvm::AllocaInst *original_ai = original_allocas_by_position[key];
                                    
                                    bool is_explicit = false;
                                    for (const auto& evar : explicit_vars) {
                                        if (evar.variable == original_ai) {
                                            is_explicit = true;
                                            break;
                                        }
                                    }
                                    
                                    if (!is_explicit) {
                                        SensitiveVar derived_var;
                                        derived_var.variable = original_ai;
                                        derived_var.location = original_ai;
                                        derived_var.isGlobal = false;
                                        derived_var.name = original_ai->hasName() ? original_ai->getName().str() : ("<derived_" + std::to_string(alloca_idx) + ">");
                                        
                                        derived_vars.push_back(derived_var);
                                        log_print("Tainted alloca: " + derived_var.name + " (position " + std::to_string(alloca_idx) + " in " + func_name + ")");
                                    }
                                } else {
                                    log_print("WARNING: Could not map PhASAR alloca at position " + std::to_string(alloca_idx) + " in " + func_name);
                                }
                            }
                        }
                        // check if this fact is a load from a tainted alloca
                        else if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(Fact)) {
                            if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(LI->getPointerOperand())) {
                                if (!tainted_allocs.count(AI)) {
                                    tainted_allocs.insert(AI);
                                    
                                    std::string func_name = AI->getFunction() ? AI->getFunction()->getName().str() : "";
                                    int alloca_idx = 0;
                                    bool found = false;
                                    for (auto &BB : *AI->getFunction()) {
                                        for (auto &I : BB) {
                                            if (auto *CurAI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                                                if (CurAI == AI) {
                                                    found = true;
                                                    break;
                                                }
                                                alloca_idx++;
                                            }
                                        }
                                        if (found) break;
                                    }
                                    
                                    auto key = std::make_pair(func_name, alloca_idx);
                                    if (original_allocas_by_position.count(key)) {
                                        llvm::AllocaInst *original_ai = original_allocas_by_position[key];
                                        
                                        bool is_explicit = false;
                                        for (const auto& evar : explicit_vars) {
                                            if (evar.variable == original_ai) {
                                                is_explicit = true;
                                                break;
                                            }
                                        }
                                        
                                        if (!is_explicit) {
                                            SensitiveVar derived_var;
                                            derived_var.variable = original_ai;
                                            derived_var.location = original_ai;
                                            derived_var.isGlobal = false;
                                            derived_var.name = original_ai->hasName() ? original_ai->getName().str() : ("<derived_" + std::to_string(alloca_idx) + ">");
                                            
                                            derived_vars.push_back(derived_var);
                                            log_print("Tainted variable (via load): " + derived_var.name + " (position " + std::to_string(alloca_idx) + " in " + func_name + ")");
                                        }
                                    } else {
                                        log_print("WARNING: Could not map PhASAR alloca at position " + std::to_string(alloca_idx) + " in " + func_name + " (via load)");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        log_print("[PhASAR] Total facts found: " + std::to_string(total_facts));
        log_print("[PhASAR] Analysis complete! Found " + std::to_string(derived_vars.size()) + 
                  " derived sensitive variables", false, Colors::GREEN);
        
    } catch (const std::exception& e) {
        log_print("[PhASAR ERROR] " + std::string(e.what()), true);
    }
    
    // clean temp phasar bitcode file
    std::remove(phasar_bc.c_str());
    
    return derived_vars;
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

// Step 2: Generate basic bytecode from source
bool generate_bytecode(const std::string& source_file, const std::string& bitcode_file) {
    log_print("[STEP 2] Generating bytecode from source...", false, Colors::BOLD + Colors::BLUE);
    std::string cmd = clang_cmd + " -O0 -g -emit-llvm -c " + source_file + " -o " + bitcode_file;
    if (!run_command(cmd)) {
        log_print("[ERROR] Failed to generate bytecode", true);
        return false;
    }
    log_print("[STEP 2] Successfully generated: " + bitcode_file, false, Colors::GREEN);
    return true;
}

// Step 3: Parse module and identify all sensitive variables
std::vector<SensitiveVar> identify_sensitive_vars(const std::string& bitcode_file, std::shared_ptr<llvm::Module>& m) {
    log_print("[STEP 3] Identifying sensitive variables...", false, Colors::BOLD + Colors::BLUE);

    static llvm::LLVMContext context;
    static llvm::SMDiagnostic err;

    // parse the file
    m = llvm::parseIRFile(bitcode_file, err, context);
    if (!m) {
        log_print("[ERROR] Failed to parse bitcode for instrumentation", true);
        err.print("sensitaint", llvm::errs());
        return {};
    } else {
        log_print("[STEP 3] Successfully parsed bitcode: " + bitcode_file, false, Colors::GREEN);
    }
    
    auto vars = find_sensitive_vars(m);
    log_print("[STEP 3] Found " + std::to_string(vars.size()) + " sensitive variables:", false, Colors::GREEN);
    for (const auto& var : vars) {
        log_print("  - " + var.name + " (" + (var.isGlobal ? "global" : "local") + ")");
    }
    
    return vars;
}

// Step 4: Inject instructions for sensitive variables
bool inject_instructions(const std::string& input_file, const std::string& output_file, std::vector<SensitiveVar> vars, std::shared_ptr<llvm::Module> m) {
    log_print("[STEP 4] Injecting instructions...", false, Colors::BOLD + Colors::BLUE);
    
    instrument_vars(m, vars);
    
    std::error_code ec;
    llvm::raw_fd_ostream out(output_file, ec, llvm::sys::fs::OpenFlags::OF_None);
    if (ec) {
        log_print("[ERROR] Failed to write instrumented bytecode: " + ec.message(), true);
        return false;
    }
    
    WriteBitcodeToFile(*m, out);
    log_print("[STEP 4] Successfully instrumented and wrote: " + output_file, false, Colors::GREEN);
    return true;
}

// Step 5: Build final executable
bool build_executable(const std::string& bitcode_file, const std::string& executable_file) {
    log_print("[STEP 5] Building final executable...", false, Colors::BOLD + Colors::BLUE);

    // Build with no optimization
    std::string cmd = "clang -O0 " + bitcode_file + " runtime/runtime_helpers.c runtime/hashmap.c -o " + executable_file;
    if (!run_command(cmd)) {
        log_print("[ERROR] Failed to build executable", true);
        return false;
    }
    log_print("[STEP 5] Successfully built executable: " + executable_file, false, Colors::GREEN);
    return true;
}

// Step 6: Clean up temporary files
void cleanup_temp_files(const std::vector<std::string>& temp_files) {
    log_print("[STEP 6] Cleaning up temporary files...", false, Colors::BOLD + Colors::BLUE);
    for (const auto& file : temp_files) {
        std::string cmd = "rm -f " + file;
        run_command(cmd);
        log_print("  - Removed: " + file);
    }
    log_print("[STEP 6] Cleanup complete");
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
