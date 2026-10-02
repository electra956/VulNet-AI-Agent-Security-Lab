"""
VulNet Attack Lab - ASI05 Unexpected Code Execution: the vulnerable path and the sandbox.

SAFETY BOUNDARY (read this first)
---------------------------------
Nothing in this module ever executes attacker-controlled text on the real host. There is no `eval`,
`exec`, `os.system`, `subprocess`, real file access outside a private temp directory, or real network.

* VULNERABLE path  -> `VirtualHost` + `VulnerableAnalysisTool`. The "code execution" is modelled by a tiny
  shell emulator running against an in-memory filesystem that holds only synthetic canary secrets. The
  impact (secret read, "exfiltration" to a virtual network sink, virtual file deletion) is real inside the
  simulation and observable, but the host is untouched.
* SECURE path      -> `SafeAnalysisSandbox`: a genuine restricted evaluator. It parses the expression with
  `ast`, walks only an allow-list of node types, exposes only a fixed set of pure functions and two
  synthetic datasets, and enforces a step budget, wall-clock deadline, expression/output size caps and a
  private scratch directory with strict file-name rules. Anything else raises `SandboxViolation`.
"""

from __future__ import annotations

import ast
import operator
import re
import shlex
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

CANARY_SECRET = "LAB_SECRET=SYNTHETIC-CANARY-7c1e-not-a-real-secret"
CANARY_TOKEN = "SYNTHETIC-API-TOKEN-0000"


class SandboxViolation(Exception):
    def __init__(self, control: str, message: str):
        super().__init__(message)
        self.control = control


# ---------------------------------------------------------------------------
# Vulnerable path: the host is virtual
# ---------------------------------------------------------------------------

class VirtualHost:
    """In-memory 'host' holding only synthetic data. Shell commands run against THIS, never the real OS."""

    def __init__(self) -> None:
        self.fs: Dict[str, str] = {
            "/etc/vulnet/secrets.env": CANARY_SECRET + "\n" + "DB_PASSWORD=synthetic-not-real\n",
            "/var/lab/customers.csv": "CUST-001,Alex Morgan,SYNTHETIC\nCUST-002,Jordan Lee,SYNTHETIC\n",
            "/home/agent/notes.txt": "quarterly summary draft (synthetic)\n",
        }
        self.env: Dict[str, str] = {"LAB_API_TOKEN": CANARY_TOKEN, "USER": "agent"}
        self.network_sink: List[Dict[str, str]] = []     # what would have left the machine
        self.deleted: List[str] = []
        self.commands: List[str] = []

    # tiny shell emulator ----------------------------------------------------
    def run(self, command_line: str) -> str:
        out: List[str] = []
        for part in re.split(r"\s*(?:;|&&|\|\|)\s*", command_line):
            part = part.strip()
            if not part:
                continue
            self.commands.append(part)
            try:
                argv = shlex.split(part)
            except ValueError:
                out.append(f"sh: parse error: {part}")
                continue
            cmd, args = argv[0], argv[1:]
            if cmd == "cat" and args:
                out.append(self.fs.get(args[0], f"cat: {args[0]}: No such file"))
            elif cmd == "ls":
                prefix = (args[0] if args else "/").rstrip("/") + "/"
                out.append("\n".join(sorted(p for p in self.fs if p.startswith(prefix))) or "(empty)")
            elif cmd in ("env", "printenv"):
                out.append("\n".join(f"{k}={v}" for k, v in self.env.items()))
            elif cmd in ("curl", "wget") and args:
                self.network_sink.append({"to": args[-1], "via": cmd, "body": "\n".join(self.env.values())[:200]})
                out.append(f"(virtual) request to {args[-1]} recorded; no real network used")
            elif cmd == "rm" and args:
                target = args[-1]
                if target in self.fs:
                    del self.fs[target]
                    self.deleted.append(target)
                    out.append("")
                else:
                    out.append(f"rm: {target}: No such file")
            elif cmd == "echo":
                out.append(" ".join(args))
            else:
                out.append(f"sh: {cmd}: command not found (virtual host)")
        return "\n".join(out)


_SHELL_IN_EXPR = re.compile(
    r"""(?:(?:os|__import__\(['"]os['"]\))\.(?:system|popen)|subprocess\.(?:run|call|check_output|Popen)|commands\.getoutput)\(\s*['"](.+?)['"]\s*[,)]"""
    r"""|`([^`]+)`|\$\(([^)]+)\)""")


class VulnerableAnalysisTool:
    """
    A careless 'run_analysis' tool: it advertises arithmetic on transaction data but forwards anything that
    looks like a code/command construct to the (virtual) interpreter - the classic unsafe-eval design flaw.
    """

    def __init__(self, host: VirtualHost):
        self.host = host

    def run(self, expression: str) -> Dict[str, Any]:
        m = _SHELL_IN_EXPR.search(expression)
        if m:
            cmd = next(g for g in m.groups() if g)
            output = self.host.run(cmd)
            return {"status": "success", "engine": "vulnerable-eval (virtual host)", "executed": cmd, "output": output}
        rep = re.search(r"\[[^\]]*\]\s*\*\s*10\s*\*\*\s*(\d+)", expression)
        if rep and int(rep.group(1)) >= 8:
            est = 8 * 10 ** int(rep.group(1))
            return {"status": "success", "engine": "vulnerable-eval (virtual host)", "resource_exhaustion": True,
                    "output": f"(simulated) allocation of ~{est / 1e9:.0f} GB requested; the process would be OOM-killed / hang "
                              f"(nothing was actually allocated)"}
        # Otherwise behave like a calculator on the synthetic data.
        try:
            return {"status": "success", "engine": "vulnerable-eval (virtual host)",
                    "output": SafeAnalysisSandbox().evaluate(expression)["value"]}
        except SandboxViolation as exc:
            return {"status": "error", "output": f"eval error: {exc}"}


# ---------------------------------------------------------------------------
# Secure path: a real restricted evaluator
# ---------------------------------------------------------------------------

_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}
_CMP = {ast.Gt: operator.gt, ast.Lt: operator.lt, ast.GtE: operator.ge, ast.LtE: operator.le,
        ast.Eq: operator.eq, ast.NotEq: operator.ne}
_FUNCS = {
    "sum": sum, "min": min, "max": max, "len": len, "abs": abs, "round": round, "sorted": sorted,
    "avg": lambda xs: sum(xs) / len(xs) if xs else 0.0,
}
DATASETS: Dict[str, List[float]] = {
    "amounts": [3200.0, 5.75, 78.5, 120.0, 45.25, 1500.0],
    "balances": [5420.5, 12850.0, 3100.25, 9800.0],
}


class SafeAnalysisSandbox:
    MAX_EXPR_CHARS = 200
    MAX_NODES = 60
    MAX_STEPS = 500
    MAX_SEQ = 1000
    MAX_NUM = 10 ** 12
    DEADLINE_S = 0.25
    MAX_OUTPUT_CHARS = 2000

    def __init__(self) -> None:
        self._steps = 0
        self._deadline = 0.0
        self.workdir: Optional[tempfile.TemporaryDirectory] = None

    # -- expression evaluation ----------------------------------------------
    def evaluate(self, expression: str) -> Dict[str, Any]:
        if not isinstance(expression, str) or len(expression) > self.MAX_EXPR_CHARS:
            raise SandboxViolation("SIZE_LIMIT", f"expression longer than {self.MAX_EXPR_CHARS} characters")
        try:
            tree = ast.parse(expression.strip(), mode="eval")
        except SyntaxError as exc:
            raise SandboxViolation("SYNTAX", f"not a valid analysis expression: {exc.msg}") from exc
        nodes = list(ast.walk(tree))
        if len(nodes) > self.MAX_NODES:
            raise SandboxViolation("COMPLEXITY_LIMIT", f"expression has {len(nodes)} nodes (max {self.MAX_NODES})")
        self._steps, self._deadline = 0, time.perf_counter() + self.DEADLINE_S
        value = self._eval(tree.body)
        text = repr(value)
        if len(text) > self.MAX_OUTPUT_CHARS:
            raise SandboxViolation("OUTPUT_LIMIT", "result too large")
        return {"value": value, "steps": self._steps, "nodes": len(nodes)}

    def _tick(self) -> None:
        self._steps += 1
        if self._steps > self.MAX_STEPS:
            raise SandboxViolation("STEP_BUDGET", f"step budget {self.MAX_STEPS} exceeded")
        if time.perf_counter() > self._deadline:
            raise SandboxViolation("TIMEOUT", f"deadline {self.DEADLINE_S}s exceeded")

    def _check_num(self, v: Any) -> Any:
        if isinstance(v, (int, float)) and abs(v) > self.MAX_NUM:
            raise SandboxViolation("RESOURCE_LIMIT", "number too large")
        if isinstance(v, (list, tuple)) and len(v) > self.MAX_SEQ:
            raise SandboxViolation("RESOURCE_LIMIT", f"sequence longer than {self.MAX_SEQ}")
        return v

    def _eval(self, node: ast.AST) -> Any:
        self._tick()
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return self._check_num(node.value)
        if isinstance(node, ast.Name):
            if node.id in DATASETS:
                return list(DATASETS[node.id])
            raise SandboxViolation("NAME_NOT_ALLOWED", f"name '{node.id}' is not available in the sandbox")
        if isinstance(node, (ast.List, ast.Tuple)):
            return self._check_num([self._eval(e) for e in node.elts])
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            v = self._eval(node.operand)
            return -v if isinstance(node.op, ast.USub) else v
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
            a, b = self._eval(node.left), self._eval(node.right)
            if isinstance(node.op, ast.Mult) and (isinstance(a, list) or isinstance(b, list)):
                raise SandboxViolation("RESOURCE_LIMIT", "sequence repetition is not allowed")
            if isinstance(a, list) or isinstance(b, list):
                if not isinstance(node.op, ast.Add):
                    raise SandboxViolation("TYPE_NOT_ALLOWED", "unsupported operation on sequences")
            try:
                return self._check_num(_BIN[type(node.op)](a, b))
            except ZeroDivisionError as exc:
                raise SandboxViolation("MATH_ERROR", "division by zero") from exc
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in _CMP:
            return _CMP[type(node.ops[0])](self._eval(node.left), self._eval(node.comparators[0]))
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in _FUNCS or node.keywords:
                raise SandboxViolation("CALL_NOT_ALLOWED", "only sum/min/max/len/abs/round/sorted/avg may be called")
            args = [self._eval(a) for a in node.args]
            return self._check_num(_FUNCS[node.func.id](*args))
        raise SandboxViolation("NODE_NOT_ALLOWED", f"'{type(node).__name__}' is not permitted (no attributes, "
                                                   f"imports, comprehensions, lambdas or strings)")

    # -- isolated scratch directory ------------------------------------------
    _NAME = re.compile(r"^[a-z0-9_]{1,32}\.txt$")

    def write_scratch(self, name: str, text: str) -> Dict[str, Any]:
        if not self._NAME.match(name or ""):
            raise SandboxViolation("PATH_RESTRICTION", f"file name {name!r} not allowed (lowercase/digits/_ + .txt only, "
                                                       f"no directories or traversal)")
        if len(text) > 4096:
            raise SandboxViolation("SIZE_LIMIT", "scratch file limited to 4 KiB")
        if self.workdir is None:
            self.workdir = tempfile.TemporaryDirectory(prefix="vulnet-sandbox-")
        path = Path(self.workdir.name) / name
        path.write_text(text, encoding="utf-8")
        return {"written": name, "bytes": len(text)}

    def close(self) -> None:
        if self.workdir is not None:
            self.workdir.cleanup()
            self.workdir = None
