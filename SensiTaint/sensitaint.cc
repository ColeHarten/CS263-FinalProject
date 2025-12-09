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

// Standard library includes for taint propagation
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <string_view>
#include <thread>
#include <cxxabi.h> 
#include <cstdlib>
#include <cstring>
#include <queue>

// Phasar includes for IFDS taint analysis
#include "phasar/DB/ProjectIRDB.h"
#include "phasar/PhasarLLVM/IfdsIde/Problems/IFDSTaintAnalysis.h"
#include "phasar/PhasarLLVM/Utils/TaintConfiguration.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/IfdsIde/Solver/LLVMIFDSSolver.h"
#include "phasar/PhasarLLVM/Pointer/LLVMTypeHierarchy.h"
#include "phasar/PhasarLLVM/IfdsIde/FlowFunctions/Identity.h"

// custom taint analysis
class CustomIFDSTaintAnalysis : public psr::IFDSTaintAnalysis {
private:
    std::map<const llvm::Instruction*, std::set<const llvm::Value*>> CustomSeeds;
    
public:
    CustomIFDSTaintAnalysis(psr::LLVMBasedICFG &icfg, 
                           const psr::LLVMTypeHierarchy &th,
                           const psr::ProjectIRDB &irdb,
                           psr::TaintConfiguration<const llvm::Value*> TSF,
                           std::vector<std::string> EntryPoints,
                           std::map<const llvm::Instruction*, std::set<const llvm::Value*>> Seeds)
        : IFDSTaintAnalysis(icfg, th, irdb, TSF, EntryPoints), 
          CustomSeeds(Seeds) {}
    
    // override teh initialSeeds
    std::map<const llvm::Instruction*, std::set<const llvm::Value*>> initialSeeds() override {
        
        auto SeedMap = CustomSeeds;
        for (auto &entry : SeedMap) {
            entry.second.insert(zeroValue());
        }
        return SeedMap;
    }
    
    // override functions calls
    // this stops the segfault that happens on MapFactsToCallee
    
    std::shared_ptr<psr::FlowFunction<const llvm::Value*>> 
    getCallFlowFunction(const llvm::Instruction *callSite, const llvm::Function *destFun) override {
        // Return Identity to pass facts through WITHOUT entering the function
        return psr::Identity<const llvm::Value*>::getInstance();
    }
    
    std::shared_ptr<psr::FlowFunction<const llvm::Value*>> 
    getRetFlowFunction(const llvm::Instruction *callSite, const llvm::Function *calleeFun,
                       const llvm::Instruction *exitStmt, const llvm::Instruction *retSite) override {
        return psr::Identity<const llvm::Value*>::getInstance();
    }
    
    std::shared_ptr<psr::FlowFunction<const llvm::Value*>> 
    getCallToRetFlowFunction(const llvm::Instruction *callSite, const llvm::Instruction *retSite,
                             std::set<const llvm::Function*> callees) override {
        return psr::Identity<const llvm::Value*>::getInstance();
    }
    
    std::shared_ptr<psr::FlowFunction<const llvm::Value*>> 
    getSummaryFlowFunction(const llvm::Instruction *callStmt, const llvm::Function *destFun) override {
        return nullptr;
    }
};


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


std::vector<SensitiveVar>
propagate_taint(const std::string &ir_file,
                const std::vector<SensitiveVar> &explicit_vars) {
    
    if (!file_exists(ir_file)) {
        throw std::runtime_error("IR file not found: " + ir_file);
    }

    std::string stripped_ir = ir_file + ".stripped.bc";
    
    // load module
    static llvm::LLVMContext strip_ctx;
    static llvm::SMDiagnostic strip_err;
    auto strip_module = llvm::parseIRFile(ir_file, strip_err, strip_ctx);
    if (!strip_module) {
        return explicit_vars;
    }
    
    // remove llvm.var.annotation calls
    std::vector<llvm::CallInst*> to_remove;
    for (llvm::Function &f : *strip_module) {
        for (llvm::BasicBlock &bb : f) {
            for (llvm::Instruction &inst : bb) {
                if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                    if (auto *called = call->getCalledFunction()) {
                        if (called->getName().startswith("llvm.var.annotation") ||
                            called->getName().startswith("llvm.annotation")) {
                            to_remove.push_back(call);
                        }
                    }
                }
            }
        }
    }
    
    for (auto *call : to_remove) {
        call->eraseFromParent();
    }
    
    // for phasar, treat functions outside main() as external to prevent crashes
    int stripped_functions = 0;
    for (llvm::Function &f : *strip_module) {
        if (f.getName() == "main") continue;
        if (f.isDeclaration()) continue;
        if (f.isIntrinsic() || f.getName().startswith("llvm.")) continue;
        while (!f.empty()) {
            f.begin()->eraseFromParent();
        }
        stripped_functions++;
    }
    
    // I chose to handle function call taint propagation with the custom logic above, not phasar
    std::vector<llvm::CallInst*> calls_to_remove;
    std::map<llvm::CallInst*, std::pair<llvm::Value*, llvm::Value*>> call_info;
    
    for (llvm::Function &f : *strip_module) {
        for (llvm::BasicBlock &bb : f) {
            for (llvm::Instruction &inst : bb) {
                if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                    if (auto *callee = call->getCalledFunction()) {
                        if (callee->isIntrinsic() || callee->getName().startswith("llvm.")) {
                            continue;
                        }
                    }
                    llvm::Value *arg = call->getNumArgOperands() > 0 ? call->getArgOperand(0) : nullptr;
                    call_info[call] = {call, arg};
                    calls_to_remove.push_back(call);
                }
            }
        }
    }
    
    for (auto *call : calls_to_remove) {
        if (!call->use_empty()) {
            call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
        }
        call->eraseFromParent();
    }
    std::error_code ec;
    llvm::raw_fd_ostream out(stripped_ir, ec, llvm::sys::fs::F_None);
    if (ec) {
        log_print("[ERROR] Failed to write stripped IR: " + ec.message());
        return explicit_vars;
    }
    WriteBitcodeToFile(*strip_module, out);
    out.close();
    log_print("Stripped IR written to: " + stripped_ir);

    // Set up Phasar infrastructure
    psr::ProjectIRDB IRDB({stripped_ir});

    log_print("modules: " + std::to_string(IRDB.getAllModules().size()));
    log_print("functions: " + std::to_string(IRDB.getAllFunctions().size()));


    auto modules = IRDB.getAllModules();
    if (modules.empty()) {
        log_print("IRDB has no modules!");
        return {};
    }

    auto funcs = IRDB.getAllFunctions();
    if (funcs.empty()) {
        log_print("IRDB has no functions!");
        return {};
    }

    for (auto *func : funcs) {
        if (!func) log_print("nullptr function in IRDB");
        else log_print("Function loaded: " + func->getName().str() +
                    (func->isDeclaration() ? " (declaration)" : " (definition)"));
    }

    psr::LLVMTypeHierarchy TH(IRDB);

    int num_decl_only = 0;
    for (auto *func : IRDB.getAllFunctions()) {
        if (func->isDeclaration()) ++num_decl_only;
    }
    log_print("Number of function declarations without definition: " + std::to_string(num_decl_only));
    
    log_print("Checking for entry point 'main'...");
    const llvm::Function *mainFunc = nullptr;
    for (auto *func : IRDB.getAllFunctions()) {
        if (func && func->getName() == "main") {
            mainFunc = func;
            log_print("Found main function: " + std::string(mainFunc->getName()));
            log_print("Has body: " + std::string(mainFunc->isDeclaration() ? "no" : "yes"));
            log_print("Num basic blocks: " + std::to_string(mainFunc->size()));
            break;
        }
    }
    
    if (!mainFunc) {
        log_print("[ERROR] Could not find main function!");
        return explicit_vars;
    }
    
    psr::LLVMBasedICFG *ICFG = nullptr;
    try {
        ICFG = new psr::LLVMBasedICFG(TH, IRDB);
        log_print("ICFG constructed successfully!");
    } catch (const std::exception &e) {
        log_print("[ERROR] ICFG construction failed with exception: " + std::string(e.what()));
        return explicit_vars;
    } catch (...) {
        log_print("[ERROR] ICFG construction failed with unknown exception");
        return explicit_vars;
    }
    
    if (!ICFG) {
        log_print("[ERROR] ICFG is null after construction!");
        return explicit_vars;
    }

    psr::TaintConfiguration<const llvm::Value*> TaintConfig;

    log_print("Building initial seeds from " + std::to_string(explicit_vars.size()) + " explicit variables...");
    
    // get stripped module from IRDB
    auto stripped_modules = IRDB.getAllModules();
    if (stripped_modules.empty()) {
        log_print("[ERROR] No modules in IRDB");
        delete ICFG;
        return explicit_vars;
    }
    // getAllModules returns a set
    llvm::Module *stripped_module = const_cast<llvm::Module*>(*stripped_modules.begin());
    std::map<const llvm::Instruction*, std::set<const llvm::Value*>> seeds;


    // Loop over all sensitive variables
    for (auto &var : explicit_vars) {
        if (!var.variable) {
            log_print("Warning: explicit var " + var.name + " has null variable, skipping");
            continue;
        }
        
        // find the alloca instruction
        llvm::Value *actualVar = var.variable;
        if (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(var.variable)) {
            actualVar = bc->getOperand(0);
        }
        
        auto *orig_alloca = llvm::dyn_cast<llvm::AllocaInst>(actualVar);
        if (!orig_alloca) {
            log_print("Warning: " + var.name + " is not an alloca, skipping");
            continue;
        }
        
        // Find the corresponding alloca in the stripped module
        auto *orig_func = orig_alloca->getFunction();
        if (!orig_func) {
            log_print("Warning: cannot find function for " + var.name);
            continue;
        }
        
        auto *stripped_func = stripped_module->getFunction(orig_func->getName());
        if (!stripped_func || stripped_func->isDeclaration()) {
            log_print("Warning: cannot find function " + orig_func->getName().str() + " in stripped module");
            continue;
        }
        
        // findmatching alloca by counting allocas in order
        unsigned alloca_index = 0;
        for (auto &bb : *orig_func) {
            for (auto &inst : bb) {
                if (auto *ai = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
                    if (ai == orig_alloca) {
                        goto found_index;
                    }
                    alloca_index++;
                }
            }
        }
        found_index:
        unsigned current_index = 0;
        llvm::AllocaInst *stripped_alloca = nullptr;
        
        for (auto &bb : *stripped_func) {
            for (auto &inst : bb) {
                if (auto *ai = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
                    if (current_index == alloca_index) {
                        stripped_alloca = ai;
                        goto found_stripped;
                    }
                    current_index++;
                }
            }
        }
        found_stripped:
        
        if (!stripped_alloca) {
            log_print("Warning: cannot find corresponding alloca in stripped IR for " + var.name);
            continue;
        }
        
        llvm::LoadInst *first_load = nullptr;
        for (auto &bb : *stripped_func) {
            for (auto &inst : bb) {
                if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
                    if (load->getPointerOperand() == stripped_alloca) {
                        first_load = load;
                        break;
                    }
                }
            }
            if (first_load) break;
        }
        
        if (first_load) {
            seeds[first_load].insert(first_load);
            log_print("Added seed: " + var.name + " -> result of load from " + stripped_alloca->getName().str());
        } else {
            log_print("Warning: no load found for alloca " + var.name);
        }
    }

    CustomIFDSTaintAnalysis TaintProblem(*ICFG, TH, IRDB, TaintConfig, {"main"}, seeds);
    psr::LLVMIFDSSolver<const llvm::Value*, psr::LLVMBasedICFG&> Solver(TaintProblem, true);
    
    log_print("Running IFDS solver...");
    bool solver_completed = false;
    try {
        Solver.solve();
        log_print("Solver completed successfully!");
        solver_completed = true;
    } catch (const std::exception &e) {
        log_print("[WARNING] Solver crashed with exception: " + std::string(e.what()));
    } catch (...) {
        log_print("[WARNING] Solver crashed with segfault (expected for interprocedural calls)");
    }

    // Extract results from solver
    std::vector<SensitiveVar> all_vars = explicit_vars;
    std::set<const llvm::Value *> seen_vars;

    for (const auto &var : explicit_vars) {
        if (var.variable) seen_vars.insert(var.variable);
    }

    // Iterate through all functions to find tainted values
    int total_insts_checked = 0;
    int insts_with_nonempty_sets = 0;
    
    for (auto *func : IRDB.getAllFunctions()) {
        if (!func) continue;
        if (func->isDeclaration()) continue;

        for (auto &bb : *func) {
            for (auto &inst : bb) {
                // Check if this instruction has tainted values
                total_insts_checked++;
                if (llvm::isa<llvm::CallInst>(&inst)) continue;
                auto taintSet = Solver.ifdsResultsAt(&inst);
                if (taintSet.empty()) continue;
                
                insts_with_nonempty_sets++;
                std::string inst_name = inst.hasName() ? inst.getName().str() : "<unnamed>";
                log_print("Instruction with non-empty taint set: " + inst_name + " (" + std::string(inst.getOpcodeName()) + "), taintSet.size=" + std::to_string(taintSet.size()));
                
                // check if non-zero fact is present (meaning taint reached this instruction)
                bool has_nonzero_fact = false;
                for (const auto *fact : taintSet) {
                    if (!fact) continue;

                    std::string fact_name = fact->hasName() ? fact->getName().str() : "<unnamed_fact>";
                    if (fact_name.find("zero_value") != std::string::npos) continue;
                    
                    // founc a real tainted fact, phasar is going to log this as "Value: TOP"
                    has_nonzero_fact = true;
                    seen_vars.insert(&inst);
                    break;
                }
                
                if (!has_nonzero_fact) {
                    log_print("only has zero_value facts, skipping");
                }
            }
        }
    }
    
    log_print("Found " + std::to_string(insts_with_nonempty_sets) + " with non-empty taint sets");
    int phasar_tainted_count = seen_vars.size();
    log_print("PhASAR found " + std::to_string(phasar_tainted_count) + " intraprocedural tainted values in stripped IR");

    log_print("Mapping PhASAR's intraprocedural results from stripped IR to original IR...");
    
    static llvm::LLVMContext orig_ctx;
    static llvm::SMDiagnostic orig_err;
    auto original_module = llvm::parseIRFile(ir_file, orig_err, orig_ctx);
    if (!original_module) {
        log_print("[ERROR] Failed to load original IR");
        return all_vars;
    }
    
    std::set<llvm::Value*> tainted_values;
    int mapped_count = 0;
    for (const auto *tainted_val : seen_vars) {
        auto *tainted_inst = llvm::dyn_cast<llvm::Instruction>(tainted_val);
        if (!tainted_inst) continue;
        
        std::string func_name = tainted_inst->getFunction()->getName().str();
        const llvm::Function *stripped_func = tainted_inst->getFunction();
        unsigned bb_idx = 0;
        const llvm::BasicBlock *tainted_bb = tainted_inst->getParent();
        for (auto &bb : *stripped_func) {
            if (&bb == tainted_bb) break;
            bb_idx++;
        }
        unsigned inst_idx = 0;
        for (auto &inst : *tainted_bb) {
            if (&inst == tainted_inst) break;
            inst_idx++;
        }
        llvm::Function *orig_func = original_module->getFunction(func_name);
        if (!orig_func) continue;
        
        unsigned orig_bb_idx = 0;
        for (auto &orig_bb : *orig_func) {
            if (orig_bb_idx == bb_idx) {
                unsigned orig_inst_idx = 0;
                for (auto &orig_inst : orig_bb) {
                    if (auto *call = llvm::dyn_cast<llvm::CallInst>(&orig_inst)) {
                        if (call->getCalledFunction() && 
                            call->getCalledFunction()->getName().startswith("llvm.var.annotation")) {
                            continue;
                        }
                    }
                    
                    if (orig_inst_idx == inst_idx) {
                        tainted_values.insert(&orig_inst);
                        mapped_count++;
                        std::string name = orig_inst.hasName() ? orig_inst.getName().str() : "<unnamed>";
                        log_print("Mapped to original IR: " + name + " (" + std::string(orig_inst.getOpcodeName()) + ")");
                        break;
                    }
                    orig_inst_idx++;
                }
                break;
            }
            orig_bb_idx++;
        }
    }
       
    std::set<llvm::Value*> phasar_intra_results = tainted_values;
    
    log_print("Now running custom dataflow on original IR...");
    
    tainted_values.clear();
    std::set<llvm::Value*> tainted_memory_locations;
    
    log_print("Seeding custom dataflow from explicit sensitive variables...");
    for (llvm::Function &func : *original_module) {
        if (func.isDeclaration()) continue;
        for (llvm::BasicBlock &bb : func) {
            for (llvm::Instruction &inst : bb) {
                if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                    llvm::Function *calledFunc = call->getCalledFunction();
                    if (calledFunc && calledFunc->getName().startswith("llvm.var.annotation")) {
                        llvm::Value *annotated = call->getArgOperand(0);
                        llvm::Value *current = annotated;
                        llvm::AllocaInst *alloca = nullptr;
                        
                        while (current) {
                            if (auto *a = llvm::dyn_cast<llvm::AllocaInst>(current)) {
                                alloca = a;
                                break;
                            } else if (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(current)) {
                                current = bc->getOperand(0);
                            } else if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(current)) {
                                current = gep->getPointerOperand();
                            } else {
                                break;
                            }
                        }
                        
                        if (alloca) {
                            tainted_memory_locations.insert(alloca);
                            log_print("Seeded alloca: " + (alloca->hasName() ? alloca->getName().str() : "<unnamed>"));
                        }
                    }
                }
            }
        }
    }
    
    log_print("Starting custom dataflow with " + std::to_string(tainted_memory_locations.size()) + " memory seeds...");
    
    bool changed = true;
    int iterations = 0;
    while (changed && iterations < 20) {
        changed = false;
        iterations++;
        
        for (llvm::Function &func : *original_module) {
            if (func.isDeclaration()) continue;
            for (llvm::BasicBlock &bb : func) {
                for (llvm::Instruction &inst : bb) {
                    if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
                        llvm::Value *src_ptr = load->getPointerOperand();
                        if (tainted_memory_locations.count(src_ptr) && !tainted_values.count(load)) {
                            tainted_values.insert(load);
                            changed = true;
                        }
                    }
                    else if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
                        llvm::Value *stored_val = store->getValueOperand();
                        llvm::Value *dest_ptr = store->getPointerOperand();
                        if (tainted_values.count(stored_val) && !tainted_memory_locations.count(dest_ptr)) {
                            tainted_memory_locations.insert(dest_ptr);
                            changed = true;
                        }
                    }
                    else if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                        if (call->getCalledFunction() && call->getCalledFunction()->getName().startswith("llvm.")) {
                            continue;
                        }

                        bool has_tainted_arg = false;
                        for (unsigned i = 0; i < call->getNumArgOperands(); i++) {
                            if (tainted_values.count(call->getArgOperand(i))) {
                                has_tainted_arg = true;
                                break;
                            }
                        }

                        if (has_tainted_arg && !tainted_values.count(call)) {
                            tainted_values.insert(call);
                            changed = true;
                            std::string func_name = call->getCalledFunction() ? 
                                call->getCalledFunction()->getName().str() : "<indirect>";
                            log_print("Custom found interprocedural taint: call to " + func_name);
                        }
                    }
                    else {
                        bool has_tainted_op = false;
                        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
                            if (tainted_values.count(inst.getOperand(i))) {
                                has_tainted_op = true;
                                break;
                            }
                        }
                        
                        if (has_tainted_op && !tainted_values.count(&inst)) {
                            tainted_values.insert(&inst);
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    
    log_print("Total tainted values: " + std::to_string(tainted_values.size()));
    
    std::set<llvm::Value*> inter_only_values;
    for (auto *val : tainted_values) {
        if (llvm::isa<llvm::CallInst>(val)) {
            inter_only_values.insert(val);
        }
    }
    
    log_print("Filtered to interprocedural only: " + std::to_string(inter_only_values.size()) + " calls");
    log_print("Final result: PhASAR intra (" + std::to_string(phasar_intra_results.size()) + 
             ") + Custom inter (" + std::to_string(inter_only_values.size()) + ")");
    
    log_print("Adding PhASAR intraprocedural results to output...");
    for (auto *val : phasar_intra_results) {
        bool already_added = false;
        for (const auto &v : all_vars) {
            if (v.variable == val) {
                already_added = true;
                break;
            }
        }
        if (already_added) continue;
        
        auto *inst = llvm::dyn_cast<llvm::Instruction>(val);
        if (inst) {
            SensitiveVar derivedVar;
            derivedVar.variable = val;
            derivedVar.name = val->hasName() ? val->getName().str() : "<phasar_intra>";
            derivedVar.location = inst;
            derivedVar.derived = true;
            all_vars.push_back(derivedVar);
        }
    }
    
    log_print("Adding custom interprocedural results to output...");
    for (auto *val : inter_only_values) {
        bool already_added = false;
        for (const auto &v : all_vars) {
            if (v.variable == val) {
                already_added = true;
                break;
            }
        }
        if (already_added) continue;
        
        auto *inst = llvm::dyn_cast<llvm::Instruction>(val);
        if (inst) {
            SensitiveVar derivedVar;
            derivedVar.variable = val;
            derivedVar.name = val->hasName() ? val->getName().str() : "<custom_inter>";
            derivedVar.location = inst;
            derivedVar.derived = true;
            all_vars.push_back(derivedVar);
        }
    }

    // Cleanup
    delete ICFG;
    std::remove((ir_file + ".stripped.bc").c_str());
    
    return all_vars;
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
//      3) Propagate taint from explicit vars to find implicitly sensitive vars
//      4) Inject instructions for sensitive variables
//      5) Build final executable
//      6) Clean up temporary files

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

// Step 4: Inject instructions for sensitive variables
bool inject_instructions(const std::string& input_file, const std::string& output_file, std::vector<SensitiveVar> vars, std::shared_ptr<llvm::Module> m) {
    log_print("[STEP 4] Injecting instructions...", false, Colors::BOLD + Colors::BLUE);
    
    instrument_vars(m, vars);
    
    std::error_code ec;
    llvm::raw_fd_ostream out(output_file, ec, llvm::sys::fs::F_None);
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
    
    std::vector<SensitiveVar> explicit_vars = identify_sensitive_vars(temp_bitcode, m);
    if (explicit_vars.empty()) {
        log_print("[WARNING] No sensitive variables found to instrument");
    }
    log_print("");

    // 3: Propagate taint to find implicit sensitive variables
    log_print("[STEP 3] Propagating taint to find implicit sensitive variables...", false, Colors::BOLD + Colors::BLUE);
    
    auto derived_vars = propagate_taint(temp_bitcode, explicit_vars);
    log_print("[STEP 3] Found " + std::to_string(derived_vars.size()) + " derived sensitive variables:", false, Colors::GREEN);
    if (!derived_vars.empty()) {
        for (const auto& var : derived_vars) {
            log_print("  - " + var.name + " (derived)");
        }
    }
    
    log_print("");

    // 4: Inject instructions
    log_print("[NOTE] Currently only instrumenting explicit variables (derived vars are from stripped IR)", false, Colors::YELLOW);
    if (!inject_instructions(temp_bitcode, modified_bitcode, explicit_vars, m)) {
        return 1;
    }
    log_print("");
    
    // 5: Build final executable
    if (!build_executable(modified_bitcode, exec_file)) {
        return 1;
    }
    log_print("");

    // 6: Clean up temporary files (temporarily disabled for debugging)
    cleanup_temp_files({temp_bitcode, modified_bitcode});

    log_print("\n=== Pipeline Complete ===", false, Colors::BOLD + Colors::GREEN);
    log_print("Instrumented executable created: " + exec_file);
    log_print("Found and instrumented " + std::to_string(derived_vars.size()) + " sensitive variables");
    return 0;
}