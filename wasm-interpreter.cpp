#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <map>
#include <cassert>
#include <bit>  

// data structures
struct FuncType {
    std::vector<uint8_t> params;
    std::vector<uint8_t> results;
};

struct Module {
    std::vector<FuncType> types;
    std::vector<uint32_t> func_types; // each function’s type index
};

struct Memory {
    std::vector<uint8_t> data;
    Memory(size_t pages = 1) { data.resize(pages * 65536); } // 64 KiB per page
};

struct Global {
    int32_t value;
    bool mutable_flag;
};

struct VM {
    std::vector<int32_t> stack;
    Memory memory;
    std::vector<Global> globals;

    void push(int32_t v) { stack.push_back(v); }
    int32_t pop() {
        if (stack.empty()) throw std::runtime_error("Stack underflow");
        int32_t v = stack.back();
        stack.pop_back();
        return v;
    }
};


/*
    ULEB128 (Unsigned Little Endian Base 128)

    Each byte contributes 7 bits of data (lower bits).
    The highest bit (0x80) indicates whether more bytes follow.

    Example:
        Decode [0xE5, 0x8E, 0x26] which is 624485 in decimal

        Byte 0 = 0xE5 (1110 0101)
        Result = 1100101 = 101

        Byte 1 = 0x8E (1000 1110)
        Result = 0001110 1100101 = 1893

        Byte 2 = 0x26 (0010 0110)
        Result = 0100110 0001110 1100101 = 624485

*/
uint32_t read_uleb128(const std::vector<uint8_t>& bytes, size_t& offset) {
    
    uint32_t result = 0;
    int shift = 0;
    
    while (true) {
        uint8_t byte = bytes[offset++];
        result |= (byte & 0x7F) << shift; // Multiplying by 0111 1111 to remove continuation bit
        if ((byte & 0x80) == 0) break; // Multiplying by 1000 0000 to only account for continuation bit, is that it is 0, we stop
        shift += 7;
    }
    
    return result;
}

/*
	Needed for the i32.const instruction because it can represent negative numbers.
*/
int32_t read_sleb128(const std::vector<uint8_t>& bytes, size_t& offset) {
    
    int32_t result = 0;
    int shift = 0;
    uint8_t byte;

    while (true) {
        byte = bytes[offset++];
        result |= (byte & 0x7F) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) break;
    }

    // Sign bit of last byte set?
    if ((shift < 32) && (byte & 0x40))
        result |= -(1 << shift);

    return result;
}

/*
	Executes a sequence of instructions. Main logic of the interpreter.

    Reference:
        https://webassembly.github.io/spec/core/binary/instructions.html#numeric-instructions
*/
void execute_instructions(VM& vm, std::vector<int32_t>& locals, const std::vector<uint8_t>& bytes, size_t& offset, size_t end){
   
    while (offset < end) {
        
        uint8_t opcode = bytes[offset++];

        switch (opcode) {
        
        case 0x41: { // i32.const
            uint32_t val = read_sleb128(bytes, offset);
            vm.push(val);
            break;
        }
        
        case 0x6A: { // i32.add
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a + b);
            break;
        }
        
        case 0x6B: { // i32.sub
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a - b);
            break;
        }
        
        case 0x6C: { // i32.mul
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a * b);
            break;
        }
        
        case 0x6D: { // i32.div_s (signed division)
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            if (b == 0) {
                std::cerr << "Division by zero\n";
                return;
            }
            vm.push(a / b);
            break;
        }
        
        case 0x6E: { // i32.div_u (unsigned division)
            uint32_t b = vm.pop();
            uint32_t a = vm.pop();
            if (b == 0) {
                std::cerr << "Division by zero\n";
                return;
            }
            vm.push(a / b);
            break;
        }
        
        case 0x6F: { // i32.rem_s (signed remainder)
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            if (b == 0) {
                std::cerr << "Division by zero\n";
                return;
            }
            vm.push(a % b);
            break;
        }
        
        case 0x71: { // i32.and
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a & b);
            break;
        }
        
        case 0x72: { // i32.or
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a | b);
            break;
        }
        
        case 0x73: { // i32.xor
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a ^ b);
            break;
        }
        
        case 0x74: { // i32.shl
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a << (b & 31)); // only lower 5 bits matter for shift amount
            break;
        }
        
        case 0x75: { // i32.shr_s (signed)
            int32_t b = vm.pop();
            uint32_t ua = vm.pop();           // pop as unsigned
            int32_t a = static_cast<int32_t>(ua); // reinterpret bits as signed
            vm.push(a >> (b & 31));           // arithmetic right shift with sign
            break;
        }

        case 0x76: { // i32.shr_u (unsigned)
            int32_t b = vm.pop();
            uint32_t a = (uint32_t)vm.pop();
            vm.push((int32_t)(a >> (b & 31))); // logical right shift fills with zeros
            break;
        }
        
        case 0x36: { // i32.store
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            int32_t value = vm.pop();
            uint32_t addr = vm.pop() + offset_imm;
            // Write little-endian
            vm.memory.data[addr + 0] = (value) & 0xFF;
            vm.memory.data[addr + 1] = (value >> 8) & 0xFF;
            vm.memory.data[addr + 2] = (value >> 16) & 0xFF;
            vm.memory.data[addr + 3] = (value >> 24) & 0xFF;
            break;
        }
        
        case 0x28: { // i32.load
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            uint32_t addr = vm.pop() + offset_imm;

            // Read 4 bytes (little-endian)
            int32_t value =
                (vm.memory.data[addr + 0]) |
                (vm.memory.data[addr + 1] << 8) |
                (vm.memory.data[addr + 2] << 16) |
                (vm.memory.data[addr + 3] << 24);

            vm.push(value);
            break;
        }

        case 0x3A: { // i32.store8
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            int32_t value = vm.pop();
            uint32_t addr = vm.pop() + offset_imm;

            vm.memory.data[addr] = static_cast<uint8_t>(value & 0xFF);
            break;
        }

        case 0x2D: { // i32.load8_u
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            uint32_t addr = vm.pop() + offset_imm;

            uint8_t byte = vm.memory.data[addr];
            vm.push(static_cast<int32_t>(byte)); // zero-extend
            break;
        }

        case 0x2C: { // i32.load8_s
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            uint32_t addr = vm.pop() + offset_imm;

            int8_t byte = static_cast<int8_t>(vm.memory.data[addr]);
            vm.push(static_cast<int32_t>(byte)); // sign-extend
            break;
        }
        
        case 0x20: { // local.get
            uint32_t index = read_uleb128(bytes, offset);
            vm.push(locals[index]);
            break;
        }

        case 0x21: { // local.set
            uint32_t index = read_uleb128(bytes, offset);
            int32_t value = vm.pop();
            locals[index] = value;
            break;
        }

        case 0x22: { // local.tee
            uint32_t index = read_uleb128(bytes, offset);
            int32_t value = vm.pop();
            locals[index] = value;
            vm.push(value); // keep value on stack
            break;
        }
        
        case 0x23: { // global.get
            uint32_t index = read_uleb128(bytes, offset);
            vm.push(vm.globals[index].value);
            break;
        }
        
        case 0x24: { // global.set
            uint32_t index = read_uleb128(bytes, offset);
            if (!vm.globals[index].mutable_flag) {
                std::cerr << "Error: writing to immutable global " << index << "\n";
                break;
            }
            int32_t value = vm.pop();
            vm.globals[index].value = value;
            break;
        }
        
        case 0x45: { // i32.eqz
            int32_t a = vm.pop();
            vm.push(a == 0 ? 1 : 0);
            break;
        }
        
        case 0x46: { // i32.eq
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a == b ? 1 : 0);
            break;
        }
        
        case 0x47: { // i32.ne
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a != b ? 1 : 0);
            break;
        }
        
        case 0x48: { // i32.lt_s
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a < b ? 1 : 0);
            break;
        }
        
        case 0x49: { // i32.lt_u
            uint32_t b = vm.pop();
            uint32_t a = vm.pop();
            vm.push(a < b ? 1 : 0);
            break;
        }
        
        case 0x4A: { // i32.gt_s
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a > b ? 1 : 0);
            break;
        }
        
        case 0x4B: { // i32.gt_u
            uint32_t b = vm.pop();
            uint32_t a = vm.pop();
            vm.push(a > b ? 1 : 0);
            break;
        }
        
        case 0x4C: { // i32.le_s
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a <= b ? 1 : 0);
            break;
        }
        
        case 0x4E: { // i32.ge_s
            int32_t b = vm.pop();
            int32_t a = vm.pop();
            vm.push(a >= b ? 1 : 0);
            break;
        }
        
        case 0x67: { // i32.clz
            uint32_t a = vm.pop();
            vm.push(a == 0 ? 32 : std::countl_zero(a));
            break;
        }
        
        case 0x68: { // i32.ctz
            uint32_t a = vm.pop();
            vm.push(a == 0 ? 32 : std::countr_zero(a));
            break;
        }
        
        case 0x69: { // i32.popcnt
            uint32_t a = vm.pop();
            vm.push(std::popcount(a));
            break;
        }

        case 0x77: { // i32.rotl
            uint32_t b = vm.pop() & 31;
            uint32_t a = vm.pop();
            vm.push((a << b) | (a >> (32 - b)));
            break;
        }
        
        case 0x78: { // i32.rotr
            uint32_t b = vm.pop() & 31;
            uint32_t a = vm.pop();
            vm.push((a >> b) | (a << (32 - b)));
            break;
        }

        case 0x3B: { // i32.store16
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            int32_t value = vm.pop();
            uint32_t addr = vm.pop() + offset_imm;

            vm.memory.data[addr + 0] = value & 0xFF;
            vm.memory.data[addr + 1] = (value >> 8) & 0xFF;
            break;
        }

        case 0x2F: { // i32.load16_u
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            uint32_t addr = vm.pop() + offset_imm;

            uint16_t val = vm.memory.data[addr] |
                (vm.memory.data[addr + 1] << 8);
            vm.push(static_cast<int32_t>(val)); // zero-extend
            break;
        }

        case 0x2E: { // i32.load16_s
            uint32_t align = read_uleb128(bytes, offset);
            uint32_t offset_imm = read_uleb128(bytes, offset);
            uint32_t addr = vm.pop() + offset_imm;

            int16_t val = static_cast<int16_t>(
                vm.memory.data[addr] |
                (vm.memory.data[addr + 1] << 8));
            vm.push(static_cast<int32_t>(val)); // sign-extend
            break;
        }
        
        case 0x1B: { // select
            int32_t cond = vm.pop();
            int32_t val2 = vm.pop();
            int32_t val1 = vm.pop();
            vm.push(cond ? val1 : val2);
            break;
        }

        case 0x1A: { // drop
            vm.pop();
            break;
        }

        case 0x02: { // block
            uint8_t block_type = bytes[offset++];

            // Save the current offset position (start of block body)
            size_t block_start = offset;
            int depth = 1;

            // Find where the block ends (matching 'end')
            while (offset < end && depth > 0) {
                uint8_t op = bytes[offset++];
                if (op == 0x02) depth++;      // nested block
                else if (op == 0x0B) depth--; // end
            }
            size_t block_end = offset - 1; // one before 'end'

            // Execute block body separately
            size_t inner = block_start;
            bool broken = false;
            execute_instructions(vm, locals, bytes, inner, block_end);

            // Continue after the block
            offset = block_end + 1;
            break;
        }

        case 0x04: { // if
            uint8_t block_type = bytes[offset++];
            int32_t cond = vm.pop();

            size_t then_start = offset;
            int depth = 1;
            size_t else_pos = 0;
            size_t end_pos = 0;

            // Scan ahead to find matching else and end positions
            while (offset < end && depth > 0) {
                uint8_t op = bytes[offset++];
                if (op == 0x04) depth++;       // nested if
                else if (op == 0x05 && depth == 1 && else_pos == 0)
                    else_pos = offset;         // mark position after "else"
                else if (op == 0x0B) {
                    depth--;
                    if (depth == 0) {
                        end_pos = offset;      // mark position after "end"
                        break;
                    }
                }
            }

            if (cond) {
                size_t temp = then_start;
                size_t branch_end = (else_pos ? else_pos - 1 : end_pos - 1);
                execute_instructions(vm, locals, bytes, temp, branch_end);
            }

            else if (else_pos) {
                size_t temp = else_pos;
                execute_instructions(vm, locals, bytes, temp, end_pos - 1);
            }

            offset = end_pos; // continue after end
            break;
        }

        case 0x03: { // loop
            
            uint8_t block_type = bytes[offset++];
            size_t loop_start = offset;
            int depth = 1;

            // Find the matching end
            while (offset < end && depth > 0) {
                uint8_t op = bytes[offset++];
                if (op == 0x02 || op == 0x03) depth++; // nested block/loop
                else if (op == 0x0B) depth--;           // end
            }
            size_t loop_end = offset - 1;

            // run the loop
            while (true) {
                size_t inner = loop_start;
                size_t before = inner;
                execute_instructions(vm, locals, bytes, inner, loop_end);

                // if body executed normally, stop looping
                if (inner == before) break;
                // if br or br_if jumped out (inner advanced to loop_end), stop looping
                if (inner >= loop_end) break;
            }

            offset = loop_end + 1;
            break;
        }

        case 0x0C: { // br
            read_uleb128(bytes, offset);
            // jump to the end of the current block/loop by moving offset
            offset = end;
            break;
        }

        case 0x0D: { // br_if
            uint32_t label_idx = read_uleb128(bytes, offset);
            int32_t cond = vm.pop();
            
            if (cond) {
                offset = end; // jump out
            }
            break;
        }

        case 0x0E: { // br_table
            uint32_t count = read_uleb128(bytes, offset);
            std::vector<uint32_t> table(count);
            for (uint32_t i = 0; i < count; i++) read_uleb128(bytes, offset);
            read_uleb128(bytes, offset);
            uint32_t index = vm.pop();

            // For index==0, "fall into" first case, for others, exit early.
            if (index == 0)
                ; // continue, stay inside current block
            else
                offset = end; // jump out
            break;
        }

        case 0x05: // else (handled inside 0x04)
           
        case 0x0B: // end
            return;
        
        default:
            std::cerr << "Unknown opcode 0x" << std::hex << (int)opcode << std::dec << std::endl;
            return;
        }
    }
}

/*
    Executes all functions defined in the Code Section.

    This function iterates through all compiled functions,
    executes them, and compares the resulting memory
    output against expected test results (for validation only).

    The expected results were written manually/hardcoded

*/
void execute_code_section(VM& vm, const std::vector<uint8_t>& bytes, size_t& offset, size_t end) {
    
    uint32_t func_count = read_uleb128(bytes, offset);
    
    std::cout << "Found " << func_count << " functions\n";

	// Expected results for each function (hardcoded for validation)
    std::vector<int32_t> expected_results = {
        42, 15, 12, 42, 5, 6, 2, 10, 14, 6, 20, -4, 4, 99, 255, -1, 35, 15, 1, 100, 10, 142,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 28, 3, 3, 32, 16, 1, 1, 65535, -1, 32768,
        10, 20, 100, 200, 50, 1, 10, 20, 15, 15, 100, 102
    };

    int passed = 0;

    for (uint32_t i = 0; i < func_count; i++) {
        
        uint32_t body_size = read_uleb128(bytes, offset);
        size_t body_start = offset;
        size_t body_end = offset + body_size;

        uint32_t local_count = read_uleb128(bytes, offset);
        std::vector<int32_t> locals; // locals for this function
        
        for (uint32_t j = 0; j < local_count; j++) {
            uint32_t count = read_uleb128(bytes, offset);
            uint8_t type = bytes[offset++];
            for (uint32_t k = 0; k < count; k++)
                locals.push_back(0); // initialize all locals to 0
        }

        execute_instructions(vm, locals, bytes, offset, body_end);

        // Verify result
        int32_t loaded = vm.memory.data[0] | (vm.memory.data[1] << 8) | (vm.memory.data[2] << 16) | (vm.memory.data[3] << 24);

		// Check each memory result per function against expected results
        if (loaded != expected_results[i]) {
            std::cout << "Test " << i << " not passed: " << "Memory = " << loaded << " (expected " << expected_results[i] << ")\n";
        }
        else {
            passed++;
        }

        // Reset memory
        std::fill(vm.memory.data.begin(), vm.memory.data.end(), 0);

        // Reset mutable globals
        for (auto& g : vm.globals)
            if (g.mutable_flag)
                g.value = 0;

        // Move offset to end of this function body
        offset = body_end;
    
    }
    std::cout << "Summary: " << passed << " / " << func_count << " tests passed.\n";
}

/*
    Checks whether the given byte vector starts with the
    correct WASM magic number: 0x00 0x61 0x73 0x6D
    Reference: https://webassembly.github.io/spec/core/binary/modules.html
*/
bool correct_magic_number(const std::vector<uint8_t>& bytes) {
    
    if (bytes.size() < 4) return false; // safety check

    return (bytes[0] == 0x00 && bytes[1] == 0x61 && bytes[2] == 0x73 && bytes[3] == 0x6D); // Magic number should start with 0x00 0x61 0x73 0x6D 
}

/*
    Checks whether the given byte vector contains the
    correct WASM version number: 0x01 0x00 0x00 0x00 (Version 1)
    https://webassembly.github.io/spec/core/binary/modules.html
*/
bool correct_version(const std::vector<uint8_t>& bytes) {
    
    if (bytes.size() < 8) return false; // safety check

    return (bytes[4] == 0x01 && bytes[5] == 0x00 && bytes[6] == 0x00 && bytes[7] == 0x00); // Version should be 0x01 0x00 0x00 0x00
}

/*
    Parses the Type Section

    Each entry defines a function signature (parameter and result types)
    referenced by the Function Section.

    Example from 01_test.wat:
        
        (func (;0;) (type 0))

    Encoded bytes:
        01 05 01 60 00 00

        01 section_id (Type section)
        05 section_size (5 bytes)
        01 count (1 type)
        60 form (function type)
        00 param_count (0 parameters)
        00 result_count (0 results)

    We start the offset at position count
*/
void parse_type_section(Module& module, const std::vector<uint8_t>& bytes, size_t& offset, size_t end) {
    
    uint32_t count = read_uleb128(bytes, offset);
    
    for (uint32_t i = 0; i < count; i++) {
        uint8_t form = bytes[offset++];
    
        assert(form == 0x60); // must be 0x60 for "func"
        
        uint32_t param_count = read_uleb128(bytes, offset);
        std::vector<uint8_t> params(param_count);
        
        for (uint32_t j = 0; j < param_count; j++) {
            params[j] = bytes[offset++];
        }
        
        uint32_t result_count = read_uleb128(bytes, offset);
        
        std::vector<uint8_t> results(result_count);
        
        for (uint32_t j = 0; j < result_count; j++) {
            results[j] = bytes[offset++];
        }
        
        module.types.push_back({ params, results });
    }
    
    assert(offset == end); // Ensure the entire Type Section has been parsed
    
}

/*
    Parses the Global Section

    Each global entry defines a variable:
      - value type (e.g., 0x7F = i32)
      - mutability flag (0x00 = const, 0x01 = mutable)
      - end opcode (0x0B)
*/
void parse_global_section(VM& vm, const std::vector<uint8_t>& bytes, size_t& offset, size_t end) {
    
    uint32_t global_count = read_uleb128(bytes, offset);

    for (uint32_t i = 0; i < global_count; i++) {
        uint8_t val_type = bytes[offset++];   // e.g. 0x7F = i32
        uint8_t mut_flag = bytes[offset++];   // 0x00 = const, 0x01 = mutable

        uint8_t opcode = bytes[offset++];     // should be 0x41 (i32.const)
        
        assert(opcode == 0x41);
        
        int32_t value = static_cast<int32_t>(read_uleb128(bytes, offset));
        uint8_t end_opcode = bytes[offset++]; // should be 0x0B (end)
        
        assert(end_opcode == 0x0B);

        vm.globals.push_back({ value, mut_flag == 0x01 });

    }

    assert(offset == end);
}

/*
    Parses the Function Section

    Each entry maps a function index to a corresponding type index from the Type Section.

    Example:
        (func (;0;) (type 0) // Type Section
          i32.const 0
          i32.const 42
          i32.store)

    Encoded bytes:
        03 03 02 00 00

        03 section_id (Function section)
        03 section_size (3 bytes)
        02 count (2 functions)
        00 function 0 uses type 0
        00 function 1 uses type 0
*/
void parse_function_section(Module& module, const std::vector<uint8_t>& bytes, size_t& offset, size_t end) {
    
    uint32_t count = read_uleb128(bytes, offset);
    
    for (uint32_t i = 0; i < count; i++) {
        uint32_t type_index = read_uleb128(bytes, offset);
        module.func_types.push_back(type_index);
    }
    
    assert(offset == end); // Ensure we’ve consumed the entire section
    
}

/*
    Dispatches parsing based on the Section ID of the WASM binary.

    Implemented sections:
      1 - Type Section
      3 - Function Section
      6 - Global Section
     10 - Code Section

    These are needed for the first test 01_test.wasm.
    For a complete interpreter, the remaining sections (0, 2, 4, 5, 7–9, 11–13)
    would also need to be implemented.

    Reference:
    https://webassembly.github.io/spec/core/binary/modules.html#sections
*/
bool valid_tests(const std::vector<uint8_t>& bytes) {

    Module module;
    VM vm;
    size_t offset = 8; // Skip 8 bytes (4 magic + 4 version)

    while (offset < bytes.size()) { // Continue until all sections are processed

        uint8_t section_id = bytes[offset++];
        uint32_t section_size = read_uleb128(bytes, offset);
        size_t section_start = offset;
        size_t section_end = section_start + section_size;

        //std::cout << "Section ID: " << int(section_id) << std::endl;

        switch (section_id) {
        
		case 0: // Custom section
            offset = section_end;
            break;
        
		case 1: // Type section
            parse_type_section(module, bytes, offset, section_end);
            break;
        
		case 2: // Import section
            offset = section_end;
            break;
        
		case 3: // Function section
            parse_function_section(module, bytes, offset, section_end);
            break;
        
		case 4: // Table section
            offset = section_end;
            break;
        
		case 5: // Memory section
            offset = section_end;
            break;
        
		case 6: // Global section
            parse_global_section(vm, bytes, offset, section_end);
            break;
        
		case 7: // Export section
            offset = section_end;
            break;
        
		case 8: // Start section
            offset = section_end;
            break;
        
		case 9: // Element section
            offset = section_end;
            break;
        
		case 10: // Code section
            execute_code_section(vm, bytes, offset, section_end);
            break;
        
		case 11: // Data section
            offset = section_end;
            break;
        
		case 12: // DataCount section
            offset = section_end;
            break;
        
		case 13: // Tag section 
            offset = section_end;
            break;
        
        default:
            offset = section_end;
            break;
        }
    }
    return true;
}

// Simple WebAssembly (WASM) interpreter entry point.
// Loads a .wasm file, verifies header (magic + version), and executes validation tests.
int main(int argc, char** argv) {

    if (argc < 2) {
        std::cerr << "Usage: wasm-interpreter <file.wasm>\n";
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary); // input file stream
    
    if (!file) {
        std::cerr << "Error: Failed to open file: " << argv[1] << "\n";
        return 1;
    }

    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)),std::istreambuf_iterator<char>()); // Read entire file into a byte vector

    // Verifies Magic Number
	if (!correct_magic_number(bytes)) { // 4 bytes
        std::cerr << "Error: Invalid WASM magic number\n";
        return 1;
    }

	//Verifies Version
	if (!correct_version(bytes)) { // +4 bytes
        std::cerr << "Error: Invalid WASM Version\n";
        return 1;
    }

    std::cout << "Magic Number & Version correct\n";

	// Run the test
    if (!valid_tests(bytes)) {
        std::cout << "WASM test failed.\n";
		return 1;
    }
    
    return 0;
}
