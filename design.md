# SSL-LuaJIT

## Part 1: Core Architectural Philosophy

SSL-LuaJIT achieves near zero overhead through three strict architectural rules:
1. **Decoupled Recording and Graphification:** The interpreter records a flat, linear sequence of operations. The complex graph is only constructed in a single pass *after* the trace is closed.
2. **Structure of Arrays (SoA) over Arrays of Structures (AoS):** The high-level Intermediate Representation (IR) abandons pointer-based node objects. Instead, it uses parallel, contiguous arrays. This transforms graph traversal from random memory access (pointer chasing) into sequential memory scanning, allowing the compiler to run at memory-bandwidth speeds.
3. **Trace-Local Scope:** A trace is inherently a single-entry, single-exit straight line with one loop backedge. We exploit this to trivialize dominance, eliminate the need for complex CFG construction, and reduce multi-path dataflow analyses to simple linear sweeps.

---

## Part 2: The Self-Optimizing Interpreter

The interpreter is not just an execution engine; it is the primary profiling and optimization-hint engine. It operates using a highly optimized threaded dispatch mechanism.

### Profiling Mechanics
* **Type and Shape Profiling:** At every loop header and function entry, the interpreter maintains lightweight frequency counters for the dynamic types (integer, float, string, table) and table shapes (array-only, hash-only, mixed) of local variables.
* **Branch Outcome Profiling:** Tracks the direction of conditional jumps to predict the most likely path for trace recording.
* **Vectorization Hints:** The interpreter monitors memory access patterns. If it detects sequential, stride-1 access over arrays of numbers, or heavy independent math operations, it sets a "Vectorization Hint" flag on the trace start. This tells the JIT to bypass expensive static alias/dependency checks and aggressively apply SIMD optimizations.

### Trace Recording
When a loop or function call becomes hot, the interpreter switches to "Recording Mode." It translates bytecode into a linear stream of intermediate operations, appending them to a contiguous trace buffer. It tracks the loop backedge and any side-exits. Once the trace is closed (either by completing the loop or hitting a maximum length), the linear buffer is handed to the compiler.

---

## Part 3: IR 1 - The Structure of Arrays (SoA) Sea of Nodes

This is the high-level IR used for all major optimizations. It represents a "Sea of Nodes" where control flow, data flow, and memory state are explicitly separated but linked by integer indices.

### The Node Property Arrays
Instead of a `Node` object containing pointers, we maintain parallel, fixed-size arrays allocated from a per-trace arena.
* **Opcode Array:** Stores the specific operation (e.g., Add, TableGet, GuardType).
* **Type Tag Array:** Stores the specialized Lua type (e.g., Integer, Float, Table) proven by the interpreter.
* **Immediate/Data Array:** Stores constant values or the index of the first operand.
* **Reference Count Array:** Used for dead code elimination.
* **Cost Array:** Used for instruction selection.

### The Edge Arrays (The "Sea")
To navigate the graph without pointers, we use explicit edge arrays.
* **Data Edges:** Pairs of indices representing producer-consumer relationships for values.
* **Control Edges:** Pairs of indices representing execution dependencies (e.g., a Guard must execute before a TableGet).
* **Memory State Edges:** Pairs of indices representing abstract memory locations. Every operation that reads or writes memory (Globals, Upvalues, Tables) takes a "Memory State" node as input and outputs a new "Memory State" node. This creates a strict ordering for memory operations without requiring heavy, compile-time alias analysis.

### Lua-Specific Abstractions
* **Guards:** `GuardType`, `GuardShape`, `GuardEnv`. These act as control-flow splits. If the runtime check fails, execution diverges to a side trace.
* **Abstract Memory:** `ALoad` and `AStore` for upvalues/globals. `TGet` and `TSet` for tables. These operate on the Memory State edges.
* **Phi Nodes:** Used exclusively at the loop header to merge values from the loop pre-header and the loop backedge.

---

## Part 4: IR 2 - The Machine IR (MIR)

Once the high-level Sea of Nodes is fully optimized, it is linearized into the Machine IR. The MIR is strictly linear, register-oriented, and devoid of any graph structures.

* **Instruction Records:** A contiguous array of fixed-width records. Each record contains the target hardware opcode, the destination virtual register, source virtual registers, immediate values, and condition flags.
* **Virtual Registers:** The MIR uses an infinite supply of virtual registers. They are untyped at this stage but carry the type information from the SoA IR to guide register allocation (e.g., separating integer, float, and vector register classes).

---

## Part 5: The Optimization Pipeline (Scalar & Memory)

All optimizations on the SoA IR are executed as single-pass, forward or backward linear sweeps over the contiguous arrays. There are no worklists.

### 1. Graphification and Incremental Global Value Numbering (GVN)
As the linear trace is converted into the SoA Sea of Nodes, GVN is performed incrementally. 
* For every new operation, the compiler hashes its signature (Opcode + Operand Indices). 
* It checks a flat hash map. If an identical computation already exists in the current trace, the new node is discarded, and the existing node's index is returned. 
* This eliminates redundant arithmetic, redundant type guards, and redundant table shape checks in $O(1)$ time per node.

### 2. Partial Escape Analysis (PEA)
Lua generates massive amounts of temporary tables. PEA eliminates the allocation and garbage collection overhead for tables that do not escape the trace.
* **Forward Sweep:** The compiler tracks `TableNew` nodes in a flat virtual-allocation array. It simulates the table's fields in compiler memory.
* **Escape Tracking:** As the sweep processes `TableGet` and `TableSet` nodes, it updates the virtual table. If the table is passed to an FFI call, stored in a global, or returned from a function, it is marked as "Escaped."
* **Scalar Replacement:** If the trace ends (or loops back) and the table has not escaped, the `TableNew` node is deleted. All subsequent `TableGet` nodes are replaced by the direct scalar values stored in the virtual allocation. All `TableSet` nodes become simple register moves. The physical allocation is entirely erased.

### 3. Loop Invariant Code Motion (LICM)
* **Backward Sweep:** The compiler iterates from the loop backedge to the loop header. 
* For every node, it checks if its operands are defined outside the loop and if it has no side-effects (no memory stores, no guards). 
* If invariant, the compiler simply rewrites the node's Control Edge to point to the Loop Pre-Header instead of the Loop Body. This hoists type checks and table shape checks out of the hot loop in $O(N)$ time.

### 4. Partial Redundancy Elimination (PRE)
In a traditional CFG, PRE is complex. In a trace, it is trivialized.
* If a side-trace is recorded from a guard failure, its entry guard is checked against the root trace. If the exact same guard already exists in the root trace, the side-trace entry guard is merged/eliminated. This prevents redundant type checking across trace boundaries.

### 5. Partial Dead Code Elimination (PDCE)
* **Backward Sweep:** Using the Reference Count array, the compiler iterates backward. 
* Any node with a refcount of zero is marked as a No-Operation. The compiler then decrements the refcounts of its operands. 
* Because it is a contiguous array scan, this executes at memory-bandwidth speeds with zero pointer-chasing overhead.

---

## Part 6: The Exhaustive Vectorization Engine

Once the scalar code is clean and hoisted, the JIT applies an exhaustive suite of vectorization techniques to pack operations into hardware SIMD registers (AVX-512, NEON, SVE).

### Straight-Line & Basic Block Vectorization
1. **Superword Level Parallelism (SLP):** A sliding window scans the SoA arrays for independent, isomorphic scalar instructions (e.g., four independent Float Adds with no overlapping data edges). It packs them into a single Vector Add node.
2. **Function/Call Vectorization:** If the trace contains multiple independent calls to the same scalar math function (e.g., `math.sin`), the JIT packs the arguments into vectors and emits a single call to a vectorized math library (like Intel SVML).

### Loop Vectorization
3. **Standard Loop Vectorization (Stride-1):** Vectorizes loops iterating over contiguous memory arrays. The JIT emits vector loads, vector math, and vector stores.
4. **Outer-Loop Vectorization:** Vectorizes the outer dimension of a nested loop, treating the inner loop's result as a single vectorized operation. Crucial for matrix math.
5. **Loop Unrolling + Vectorization:** Unrolls the loop body by a factor of 4 or 8 to expose maximum Instruction-Level Parallelism (ILP), then applies SLP to the unrolled body.

### Memory Access & Irregular Vectorization
6. **Gather/Scatter Vectorization:** Vectorizes indirect memory accesses (e.g., `a[idx[i]]`) using hardware gather/scatter instructions.
7. **Interleaved Memory Access Vectorization:** Vectorizes loading/storing of interleaved data (Array of Structs). Uses hardware de-interleaving instructions to separate `x, y, z` coordinates into distinct vectors.
8. **Pointer/Induction Vectorization:** Vectorizes the calculation of memory addresses themselves to hide pointer-chasing latency.

### Control Flow & Data Pattern Vectorization
9. **Reduction Vectorization:** Vectorizes accumulations (sums, min, max, dot products). Uses vector reduction instructions to accumulate in parallel, followed by a horizontal add at the end.
10. **Masked/Predicated Vectorization:** Handles loop tails (when array size isn't a multiple of vector width) or conditional execution without branching, using vector masks to disable operations on specific lanes.
11. **Speculative Vectorization:** The dynamic language secret weapon. If the JIT cannot statically prove types or memory aliasing, it emits vector code guarded by a runtime check. If the check fails, it deoptimizes to the interpreter. This allows vectorization of code that would otherwise be left scalar.

---

## Part 7: Backend - Instruction Selection & Register Allocation

### Dynamic Programming (DP) Instruction Selection
Instead of complex tree-pattern matching, the JIT uses a Bottom-Up Dynamic Programming approach on the DAG.
* **Bottom-Up Costing:** A reverse linear sweep calculates the optimal instruction "tiles" for every node. The compiler checks a flat pattern table of hardware instructions. The cost of a node is the minimum of its pattern cost plus the costs of its operands. This guarantees the globally optimal sequence of native instructions.
* **Top-Down Emission:** A forward pass emits the native instructions recorded during the costing phase, translating the SoA nodes into the linear Machine IR.

### Linear Scan Register Allocation (LSRA)
* **Trace-Local Allocation:** The allocator only assigns physical registers for the current trace. It calculates live intervals for all virtual registers.
* **Spilling:** If physical registers are exhausted, it inserts `Spill` and `Reload` instructions into the MIR, writing to the stack.
* **ABI Reservation:** Registers required by the Lua C API (e.g., the `lua_State` pointer, the GC threshold) are hard-coded and excluded from the allocator's pool, ensuring they are never spilled.

### Peephole Optimizations
During the final emission of machine code, the emitter looks at the previously emitted instructions in the output buffer. It applies micro-optimizations on the fly, such as replacing `Move Register, 0` with `XOR Register, Register`, or folding `Add Register, 0` into a No-Op.

---

## Part 8: Runtime - Concurrent, Generational, Incremental GC

To maintain low latency and support the JIT's aggressive allocation patterns, the Garbage Collector is completely redesigned.

### Generational Heap Layout
* **Young Generation (Eden):** Uses a highly fast Copying Collector. Allocation is a simple bump-pointer. When Eden fills, a Minor GC occurs, copying surviving objects to the Survivor space and promoting them to the Old Generation.
* **Old Generation:** Uses a Mark-Sweep-Compact collector. 
* **Large Objects:** Allocated directly into the Old Generation to avoid copying overhead.

### Concurrent and Incremental Mechanics
* **Incremental Marking:** Instead of stopping the world to mark all live objects, the GC marks them in small time quanta (e.g., 1 millisecond of work) interleaved with the mutator (Lua code) execution. 
* **Concurrent Sweeping:** Dead objects are swept in background threads, returning memory to free lists without stopping the mutator.
* **Concurrent Compaction:** To prevent fragmentation, live objects in the Old Gen are moved. This is done concurrently using Read Barriers. If a thread reads an object that is currently being moved, it waits for the move to finish, then reads the new location.

### Barriers and JIT Synergy
* **Write Barriers:** To allow concurrent marking, the mutator must inform the GC whenever it modifies a pointer. The JIT emits a Write Barrier instruction after every Table Set or Upvalue Store that writes a reference type.
* **PEA Synergy:** Because Partial Escape Analysis scalar-replaces most temporary tables, they never hit the heap. Therefore, the Write Barrier is only emitted for objects that actually escape the trace. This renders the barrier overhead near zero for the vast majority of Lua code.
* **Allocation Fast Path:** The JIT emits a simple bump-pointer allocation for Young Gen objects. It checks if the bump pointer exceeds the Eden limit. If it does, it triggers a Side Trace that calls the Minor GC. This keeps the main trace pure and fast.
* **GC Roots:** The JIT maintains a shadow stack and register map during GC safepoints so the concurrent collector can accurately trace live objects held in CPU registers.

---

## Part 9: Deoptimization and Trace Linking

A tracing JIT is only as robust as its ability to handle speculation failures.

### Snapshots
Every guard and every memory allocation in the MIR is associated with a "Snapshot." A snapshot is a mapping that records exactly which Lua variables are currently held in which physical CPU registers or stack slots at that exact point in the machine code.

### Side Traces and Linking
* When a guard fails (e.g., a variable changes from Integer to String), the CPU jumps to a "Side Trace."
* The Side Trace is a separate block of compiled machine code that picks up execution from the exact state recorded in the Snapshot.
* The JIT linker patches the guard's jump instruction to point to the correct Side Trace entry point. If a Side Trace becomes hot, it can be further extended, creating a tree of traces.

### State Reconstruction
If execution falls all the way back to the interpreter (deoptimization), the interpreter uses the Snapshot to reconstruct the Lua stack, upvalues, and program counter perfectly, ensuring the script continues executing correctly without any observable state corruption.

---

## Part 10: The End-to-End Execution Flow

1. **Interpreter:** Executes bytecode. Profiles types, shapes, and branches. Sets Vectorization Hints.
2. **Recorder:** Captures a hot loop into a flat, linear trace buffer.
3. **Graphifier & GVN:** Converts the linear trace into the SoA Sea of Nodes, deduplicating redundant operations on the fly via hashing.
4. **Scalar Optimization Sweep:** 
   * *Forward:* PEA tracks and scalar-replaces non-escaping tables.
   * *Backward:* LICM hoists invariant guards; PDCE eliminates dead nodes via refcount sweeps.
5. **Vectorization Suite:** Applies SLP, Loop-Vec, Gather/Scatter, and Speculative-Vec based on the SoA structure and interpreter hints.
6. **DP Instruction Selection:** Calculates optimal hardware instruction tiles bottom-up on the DAG, then emits the linear Machine IR top-down.
7. **Register Allocation:** Assigns physical registers via Linear Scan, inserting spill code only if necessary.
8. **Code Emission:** Writes native machine code to executable memory. Inserts optimized GC Write Barriers and Allocation Checks only where PEA dictates they are necessary.
9. **Concurrent GC:** Runs continuously in background threads, performing incremental marking, sweeping, and compaction while the JIT-compiled code executes, ensuring sub-millisecond pause times.
