# ArkTS ETS Frontend

## Overview

This is the **ets_frontend** repository - the frontend compiler toolchain for the ARK Runtime Subsystem in OpenHarmony. It converts ETS (Extended TypeScript), TypeScript, and JavaScript source code into ARK bytecode (.abc files) that execute on the ARK runtime system.

**Key distinction**: This repository contains compiler toolchain only. For bytecode execution and runtime behavior, refer to the companion runtime repositories:
- `arkcompiler_runtime_core` - Core runtime infrastructure
- `arkcompiler_ets_runtime` - ETS-specific runtime implementation

## Technology Stack

- **Language**: C++17, TypeScript, JavaScript
- **Build System**: GN (Generate Ninja) with CMake support
- **Target Platforms**: Linux, Windows, macOS, openharmony-based platforms
- **Key Dependencies**: Protocol Buffers, ICU (internationalization), zlib (compression)

## Directory Structure

```
ets_frontend/
├── es2panda/              # JavaScript/TypeScript compiler (outputs es2abc)
│   ├── aot/               # Ahead-of-time compilation entry point
│   ├── binder/            # Symbol and variable binding
│   ├── compiler/          # Core compilation pipeline
│   ├── ir/                # Bytecode generation (Intermediate Representation)
│   ├── lexer/             # Lexical analysis/tokenization
│   ├── parser/            # Syntax parsing and AST construction
│   ├── typescript/        # TypeScript type definitions and handling
│   ├── util/              # Shared utilities and helpers
│   └── test/              # Compiler test suites
│
├── ets2panda/             # Enhanced ETS/ArkTS compiler
│   ├── aot/               # Ahead-of-time compilation for ETS
│   ├── ast_verifier/      # AST validation and verification
│   ├── checker/           # Type checking and semantic analysis
│   ├── compiler/          # ETS-specific compilation logic
│   ├── driver/            # Build system integration and driver
│   ├── ir/                # Enhanced IR for ETS constructs
│   ├── linter/            # Static analysis (ArkAnalyzer linter and migrate tools)
│   ├── lsp/               # Language Server Protocol implementation
│   ├── parser/            # ETS syntax parser with ArkTS extensions
│   ├── varbinder/         # Variable binding for ETS scoping rules
│   ├── public/            # Public APIs and header files
│   ├── bindings/          # Language bindings (Node.js, etc.)
│   ├── docs/              # Architecture documentation (lowering phases, etc.)
│   └── test/              # ETS compiler test infrastructure
│
├── arkguard/              # Source code obfuscation tool
│   ├── src/               # Obfuscation engine implementation
│   └── test/              # Obfuscation test cases
│
├── merge_abc/             # Bytecode file merging utility
│   ├── protos/            # Protocol buffer definitions
│   └── src/               # Merge/serialize logic
│
├── legacy_bin/            # Legacy compiler binaries (API8 compatibility)
├── test262/               # ECMAScript conformance test suite
├── testTs/                # TypeScript system tests
├── test_ecma_bcopt/       # Bytecode optimization tests
├── test/                  # SDK and XTS integration tests
│
├── BUILD.gn               # GN build configuration (primary)
├── CMakeLists.txt         # CMake build support (alternative)
├── bundle.json            # OpenHarmony bundle metadata
├── README.md              # Project overview (English)
└── README_zh.md           # Project overview (Chinese)
```

## Component Overview

### es2panda
Original JavaScript/TypeScript compiler. Generates `es2abc` executable that converts JS/TS files to ARK bytecode. Focuses on ECMAScript standard compliance with TypeScript support.

### ets2panda
Enhanced compiler for ArkTS - the language for openharmony development. Supports both ArkTS-Dyn (dynamic) and ArkTS-Sta (static) compilation modes. Includes comprehensive type checking, lowering phases, and advanced optimizations. Used as the primary compiler for ArkTS application development.

### arkguard
JavaScript/TypeScript obfuscation tool integrated into DevEco Studio. Provides name obfuscation (variables, functions, properties), code compacting, log removal, and comment removal for IP protection.

### merge_abc
Utility tool that combines multiple ARK bytecode (.abc) files into a single package using Protocol Buffers for serialization.

## Build System

**Primary build**: GN (Generate Ninja)
```bash
# Execute from repository root (openharmony/ directory)
../../build.sh --product-name rk3568 --build-target ets_frontend_build
```

**Alternative build**: CMake (for development/local builds)
```bash
cmake -B out -DCMAKE_BUILD_TYPE=Release
cmake --build out
```

### Key Build Outputs
- `out/rk3568/.../es2abc` - JavaScript/TypeScript compiler
- `out/rk3568/.../ets2panda` - ETS/ArkTS compiler
- `out/rk3568/.../merge_abc` - Bytecode merge utility

## Compilation Pipeline

Both compilers follow a multi-phase pipeline:
1. **Lexing** - Source code tokenization
2. **Parsing** - Abstract Syntax Tree (AST) generation
3. **Type Checking** - Semantic analysis (ets2panda only)
4. **Lowering** - AST transformation phases (see `ets2panda/docs/lowering-phases.md`)
5. **IR Generation** - Intermediate representation creation
6. **Bytecode Emission** - ARK bytecode (.abc) output

## Key Concepts

### Dynamic vs Static Compilation
- **es2panda**: Supports dynamic compilation patterns, closer to standard JavaScript execution model
- **ets2panda**: Supports static (AOT) compilation with full type checking for ArkTS

### ArkTS Language Variants
ArkTS is the primary language for openharmony development, with two compilation modes:

- **ArkTS-Dyn (Dynamic)**: Supports dynamic compilation patterns, closer to standard JavaScript/TypeScript execution model with more flexible typing. Compiled using es2panda.

- **ArkTS-Sta (Static)**: Statically-typed variant requiring explicit type annotations and no implicit `any`. Enables AOT compilation with full type checking and advanced optimizations. Compiled using ets2panda.

Both variants support special constructs for UI component development (`@Component`, `@State`, etc.) and structural typing with additional constraints.

## Documentation

- **Main README**: `README.md` (English), `README_zh.md` (Chinese)
- **ETS Lowering Phases**: `ets2panda/docs/lowering-phases.md` - detailed AST transformation phases
- **Linter Documentation**: `ets2panda/linter/README.md` - ArkAnalyzer static analysis rules
- **Component READMEs**: Each major subdirectory has its own README with specific details

## Testing

- **test262/** - ECMAScript standard conformance tests
- **testTs/** - TypeScript language feature tests
- **test/** - SDK compatibility and XTS tests
- Component-specific test directories in `es2panda/test/` and `ets2panda/test/`

## Related Repositories

- **arkcompiler_runtime_core**: Core runtime infrastructure
- **arkcompiler_ets_runtime**: ETS-specific runtime implementation

## Development Notes

- The `ets2panda` directory is responsible for the compilation logic of ArkTS-Sta, while the `es2panda` directory is in charge of the compilation logic of ArkTS-Dyn.
- The code comments in this repository should be written in English.
- The commit message should be written in English.
- Don't create commits directly. Have them reviewed.
