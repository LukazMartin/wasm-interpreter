# WebAssembly Interpreter – Assessment

## Overview

This project implements a **minimal WebAssembly (WASM) interpreter** in **C++**.
It supports core MVP **i32 instructions**, locals/globals, memory operations, and structured control flow.  

Main Reference: [https://webassembly.github.io/spec/core/binary/modules.html]

---

## Implemented Features

- Validation of **magic number** & **version**
- Parsing of sections: **Type (1)**, **Function (3)**, **Global (6)**, and **Code (10)**
- Instruction support:
  - **Arithmetic:** `i32.add`, `i32.sub`, `i32.mul`, `i32.div_s/u`, `i32.rem_s`
  - **Memory:** `i32.load`, `i32.store`, `load8/16_{s,u}`, `store8/16`
  - **Locals/Globals:** `local.get`, `local.set`, `local.tee`, `global.get`, `global.set`
  - **Comparison:** `i32.eq`, `i32.ne`, `i32.lt_s/u`, `i32.gt_s/u`, `i32.le_s`, `i32.ge_s`
  - **Bit operations:** `i32.rotl`, `i32.rotr`, `i32.clz`, `i32.ctz`, `i32.popcnt`
  - **Control flow:** `block`, `loop`, `if/else`, `br`, `br_if`, `br_table`, `drop`, `select`

---

## Test Results

- **Executed file:** `01_test.wasm`
- **Result:** **50 / 54 tests passed**
- Remaining unimplemented tests:
  - `_test_loop_sum (func 50)`
  - `_test_loop_early_break (func 51)`
  - `_test_br_table_case0 (func 52)`
  - `_test_br_table_case2 (func 53)`
- The interpreter resets memory and globals after each test to ensure isolation.

---

## Design Decisions

- **Architecture**
  - Modular separation between `Module` (types/functions) and `VM` (runtime state)
  - Recursive execution of nested blocks (`block`, `loop`, `if`)
  - Uses **ULEB128/SLEB128** decoders for variable-length integers
- **Validation**
  - Hardcoded `expected_results[]` array used to verify memory outputs (`memory[0]`) for `01_test.wat`

---

## Limitations

- Advanced features like `call_indirect`,  are not implemented  
- Only implementation for `01_test.wat` has been done  

---

## Build & Run

### 1. Configure and build

The compiled binary is already included.

From the folder `wasm-interpreter/out/build/x64-debug`, run:

`.\wasm-interpreter.exe ..\..\..\tests\wat\01_test.wasm`

If it fails, recompile by running:

`cmake --build . --config Debug`

### 2. Convert `.wat` to `.wasm`

The `.wat` file 01_test.wat has already been converted to `.wasm`.

If you want to convert additional files:
- https://github.com/WebAssembly/wabt/releases
- wat2wasm tests/wat/{file_name}.wat -o tests/wat/{file_name}.wasm
