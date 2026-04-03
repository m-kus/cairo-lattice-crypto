# cairo_gen/circuits/mlkem_ntt.py
"""
ML-KEM NTT circuit generator (q=3329, n=256).

Generates fully-unrolled Cairo ntt_256 function using BoundedIntCircuit.
Uses iterative Cooley-Tukey DIT with 7 butterfly layers, matching FIPS 203
Algorithm 9.
"""
from cairo_gen import BoundedIntCircuit
from cairo_gen.circuit import BoundedIntVar
from mlkem_py.constants import Q, N, zetas


class MlkemNttCircuitGenerator:
    """Generate ML-KEM NTT circuits using BoundedIntCircuit DSL."""

    Q = Q  # 3329

    def __init__(self, n: int = 256):
        """
        Initialize generator for NTT of size n.

        Args:
            n: Transform size (must be 256 for ML-KEM).
        """
        if n != 256:
            raise ValueError(f"ML-KEM NTT requires n=256, got {n}")
        self.n = n
        self.circuit = BoundedIntCircuit(f"ntt_{n}_inner", modulus=self.Q)

    def _register_constants(self) -> None:
        """Register all twiddle factor constants needed for NTT."""
        self.circuit.register_constant(self.Q, "Q")

        # Register the 127 unique zeta values used by the NTT (zetas[1..127]).
        # zetas[0] = 1 is unused by the algorithm.
        seen = set()
        for k in range(1, 128):
            val = zetas[k]
            if val not in seen:
                self.circuit.register_constant(val, f"Z{k}")
                seen.add(val)

    def _ntt_iterative(self, f: list[BoundedIntVar]) -> list[BoundedIntVar]:
        """
        Iterative Cooley-Tukey DIT NTT — traces operations into circuit.

        Matches FIPS 203 Algorithm 9 exactly:
            k = 1
            len = 128
            while len >= 2:
                for start in range(0, 256, 2*len):
                    zeta = zetas[k]; k += 1
                    for j in range(start, start + len):
                        t = zeta * f[j + len]
                        f[j + len] = f[j] - t
                        f[j] = f[j] + t
                len //= 2

        All operations are traced into the circuit via BoundedIntVar arithmetic.
        """
        k = 1
        length = 128
        while length >= 2:
            start = 0
            while start < 256:
                zeta_val = zetas[k]
                zeta = self.circuit.constant(zeta_val, f"z{k}")
                k += 1
                for j in range(start, start + length):
                    # t = zeta * f[j + length]
                    t = f[j + length] * zeta
                    # f[j + length] = f[j] - t
                    f[j + length] = f[j] - t
                    # f[j] = f[j] + t
                    f[j] = f[j] + t
                start += 2 * length
            length //= 2
        return f

    def simulate(self, values: list[int]) -> list[int]:
        """
        Execute the traced operations on actual values.

        Replays the circuit on concrete integers to verify correctness
        without generating Cairo code.
        """
        if len(values) != len(self.circuit.inputs):
            raise ValueError(
                f"Expected {len(self.circuit.inputs)} values, got {len(values)}"
            )

        env: dict[str, int] = {}

        # Initialize inputs
        for i, inp in enumerate(self.circuit.inputs):
            env[inp.name] = values[i]

        # Initialize constants
        for var_name, var in self.circuit.variables.items():
            if var.min_bound == var.max_bound and var.source is None:
                env[var_name] = var.min_bound

        # Execute operations
        for op in self.circuit.operations:
            if op.op_type == "ADD":
                a, b = op.operands
                env[op.result.name] = env[a.name] + env[b.name]
            elif op.op_type == "SUB":
                a, b = op.operands
                env[op.result.name] = env[a.name] - env[b.name]
            elif op.op_type == "MUL":
                a, b = op.operands
                env[op.result.name] = env[a.name] * env[b.name]
            elif op.op_type == "REDUCE":
                a = op.operands[0]
                modulus = op.extra.get("modulus", self.Q)
                env[op.result.name] = env[a.name] % modulus
            elif op.op_type in ("DIV", "REM"):
                a = op.operands[0]
                b = op.operands[1] if len(op.operands) > 1 else None
                divisor = env[b.name] if b else op.extra.get("modulus", self.Q)
                if op.op_type == "DIV":
                    env[op.result.name] = env[a.name] // divisor
                else:
                    env[op.result.name] = env[a.name] % divisor

        return [env[out.name] for out in self.circuit.outputs]

    def generate(self, mode: str = "bounded") -> str:
        """
        Build circuit and compile to Cairo.

        Args:
            mode: Compilation mode — "bounded" or "felt252".

        Returns:
            Cairo source code for the inner function.
        """
        self.circuit = BoundedIntCircuit(f"ntt_{self.n}_inner", modulus=self.Q)
        self._register_constants()

        # Create inputs
        inputs = [
            self.circuit.input(f"f{i}", 0, self.Q - 1)
            for i in range(self.n)
        ]

        # Run iterative NTT (traces all operations)
        outputs = self._ntt_iterative(inputs)

        # Mark outputs with reduction
        for i, out in enumerate(outputs):
            self.circuit.output(out.reduce(), f"r{i}")

        self.circuit.print_summary()

        return self.circuit.compile(mode=mode)

    def generate_full(self, mode: str = "bounded") -> str:
        """
        Generate complete Cairo file with inner function and public wrapper.

        Returns:
            Complete Cairo source file.
        """
        inner_code = self.generate(mode=mode)

        header = """// Auto-generated by cairo_gen/circuits/mlkem_ntt.py
// DO NOT EDIT MANUALLY - regenerate with: python -m cairo_gen.circuits.regenerate mlkem_ntt

"""

        wrapper = self._generate_wrapper()
        verify_wrapper = self._generate_verify_wrapper()

        return header + inner_code + wrapper + verify_wrapper

    def _generate_verify_wrapper(self) -> str:
        """Generate ntt_verify_N: NTT(hint) and assert == expected, no output array."""
        n = self.n
        hint_params = ", ".join(f"h{i}" for i in range(n))
        hint_args = ", ".join(f"upcast(h{i})" for i in range(n))
        r_names = ", ".join(f"r{i}" for i in range(n))
        asserts = "\n    ".join(
            f"assert(r{i} == *expected.at({i}), 'ntt verify');"
            for i in range(n)
        )
        return f"""
/// NTT-and-verify: asserts NTT(hint) == expected without building output array.
pub fn ntt_verify_{n}(mut hint: Span<Zq>, expected: Span<Zq>) {{
    let boxed = hint.multi_pop_front::<{n}>().expect('expected {n} hint');
    let [{hint_params}] = boxed.unbox();

    let ({r_names}) = ntt_{n}_inner({hint_args});

    {asserts}
}}
"""

    def _generate_wrapper(self) -> str:
        """Generate the public wrapper function."""
        n = self.n

        param_names = ", ".join(f"f{i}" for i in range(n))
        output_names = ", ".join(f"r{i}" for i in range(n))
        array_items = ", ".join(f"r{i}" for i in range(n))
        inner_args = ", ".join(f"upcast(f{i})" for i in range(n))

        return f"""
/// NTT of size {n} — accepts Span<Zq>, returns Array<Zq>.
pub fn ntt_{n}(mut f: Span<Zq>) -> Array<Zq> {{
    let boxed = f.multi_pop_front::<{n}>().expect('expected {n} elements');
    let [{param_names}] = boxed.unbox();

    let ({output_names}) = ntt_{n}_inner({inner_args});

    array![{array_items}]
}}
"""
