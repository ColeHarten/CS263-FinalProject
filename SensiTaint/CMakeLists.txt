cmake_minimum_required(VERSION 3.10)
project(sensitaint CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# -----------------------------
# Sanitizers
# -----------------------------
option(ENABLE_SANITIZERS "Enable sanitizers (AddressSanitizer, UBSan)" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_MSAN "Enable MemorySanitizer" OFF)

if(ENABLE_SANITIZERS OR ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
    message(STATUS "AddressSanitizer enabled")
endif()

if(ENABLE_SANITIZERS OR ENABLE_UBSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=undefined")
    message(STATUS "UndefinedBehaviorSanitizer enabled")
endif()

if(ENABLE_TSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=thread")
    message(STATUS "ThreadSanitizer enabled")
endif()

if(ENABLE_MSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=memory -fno-omit-frame-pointer")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=memory")
    message(STATUS "MemorySanitizer enabled")
endif()

# -----------------------------
# LLVM
# -----------------------------
find_package(LLVM REQUIRED CONFIG)

set(LLVM_LIBS
    LLVMCore
    LLVMSupport
    LLVMAnalysis
    LLVMIRReader
    LLVMTransformUtils
    LLVMPasses
    LLVMBitWriter
)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVM config: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
add_definitions(-DBOOST_LOG_DYN_LINK)

# -----------------------------
# Boost
# -----------------------------
find_package(Boost REQUIRED COMPONENTS
    log
    log_setup
    thread
    filesystem
    program_options
    system
    date_time
)

if(Boost_FOUND)
    message(STATUS "Found Boost: ${Boost_VERSION}")
    message(STATUS "Boost include dirs: ${Boost_INCLUDE_DIRS}")
    message(STATUS "Boost library dirs: ${Boost_LIBRARY_DIRS}")
    message(STATUS "Boost libraries: ${Boost_LIBRARIES}")
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARY_DIRS})
else()
    message(FATAL_ERROR "Boost not found")
endif()



# -----------------------------
# PhASAR (manual configuration)
# -----------------------------
find_path(PHASAR_INCLUDE_DIR 
    NAMES phasar/PhasarLLVM/IfdsIde/Problems/IFDSTaintAnalysis.h
    PATHS /usr/include /usr/local/include /opt/phasar/include
)

if(PHASAR_INCLUDE_DIR)
    message(STATUS "Found PhASAR headers in: ${PHASAR_INCLUDE_DIR}")
    include_directories(${PHASAR_INCLUDE_DIR})
else()
    message(FATAL_ERROR "PhASAR headers not found")
endif()

# Additional include directories
include_directories(/usr/local/include /usr/local/include/wise_enum)

# -----------------------------
# Sources and target
# -----------------------------
file(GLOB SOURCES *.cc)
add_executable(sensitaint ${SOURCES})

# -----------------------------
# Linking
# -----------------------------
target_link_libraries(sensitaint PRIVATE
    ${LLVM_LIBS}

    # PhASAR
    phasar_phasarllvm_utils
    phasar_controlflow
    phasar_pointer
    phasar_db
    phasar_utils
    phasar_config
    phasar_ifdside

    # Boost
    ${Boost_LIBRARIES}
    
    # Explicit Boost libraries as fallback
    boost_log
    boost_log_setup
    boost_thread
    boost_filesystem
    boost_program_options
    boost_system
    boost_date_time

    pthread
)