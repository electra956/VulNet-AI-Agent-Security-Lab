# ASI05 — Unexpected Code Execution

## Vulnerability Description
Unexpected Code Execution occurs when an agent dynamically writes, synthesizes, or accepts executable code and evaluates it directly on the host system without adequate isolation, sandboxing, or syntactic filtering.

## Attack Preconditions
- The agent provides an interpreter, scripting, or calculator tool executing code via Python `eval()` or `exec()`.
- Code inputs are passed directly to the runtime without abstract syntax tree (AST) inspection.

## Simulated Attack Input
```python
import os; os.system('whoami')
```

## Vulnerable Behavior
In Vulnerable Mode, the evaluator accepts raw code strings, demonstrating how system calls or file access commands could execute on the host.

## Security Controls
- **Abstract Syntax Tree (AST) Validation:** Code is parsed into an AST and inspected for forbidden nodes (`ast.Import`, `ast.ImportFrom`, and calls to `eval`, `exec`, `system`, or `popen`).
- **Telemetry Auditing:** Any violation logs an `UNEXPECTED_CODE_EXECUTION_BLOCKED` event.

## Secure Behavior
In Secure Mode, the AST validator detects forbidden syntax constructs and immediately halts execution before evaluation.

## Mitigation
1. Avoid dynamic `eval()` or `exec()` of LLM outputs.
2. If computation is necessary, restrict to safe expression parsers or isolated micro-VM sandboxes with dropped privileges and no network access.
