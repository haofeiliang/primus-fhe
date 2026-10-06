#!/usr/bin/env python3
"""Exact, small-ring oracle for shared-projection-analysis.md; no Rust/FFT dependency.

Run explicitly with Python 3.8+; this research check is not a CI performance test.
Automorphisms use an ideal change of secret plus a bounded injected phase error.
It checks the algebra and coefficient rounding, not actual gadget/FFT error bounds.
"""

from math import gcd
from random import Random


def add(a, b, q):
    return [(x + y) % q for x, y in zip(a, b)]


def scale(a, factor, q):
    return [factor * x % q for x in a]


def transform(a, degree, shift, q):
    """Independent signed coefficient permutation in Z_q[X]/(X^N+1)."""
    n = len(a)
    out = [0] * n
    for index, value in enumerate(a):
        exponent = (degree * index + shift) % (2 * n)
        out[exponent % n] = (value if exponent < n else -value) % q
    return out


def multiply(a, b, q):
    """Schoolbook negacyclic multiplication; deliberately no transform kernels."""
    n = len(a)
    out = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % n] += x * y * (1 if i + j < n else -1)
    return [x % q for x in out]


def inverse(a, q):
    """Solve the multiplication matrix over an odd prime or a power of two."""
    n = len(a)
    columns = [transform(a, 1, i, q) for i in range(n)]
    matrix = [[columns[j][i] for j in range(n)] + [int(i == 0)] for i in range(n)]
    for j in range(n):
        pivot = next(i for i in range(j, n) if gcd(matrix[i][j], q) == 1)
        matrix[j], matrix[pivot] = matrix[pivot], matrix[j]
        matrix[j] = scale(matrix[j], pow(matrix[j][j], -1, q), q)
        for i in range(n):
            if i != j:
                matrix[i] = add(matrix[i], scale(matrix[j], -matrix[i][j], q), q)
    result = [row[-1] for row in matrix]
    assert multiply(a, result, q) == [1] + [0] * (n - 1)
    return result


def retain(a, count):
    """Direct coefficient oracle Pi_count, independent of trace recursion."""
    stride = len(a) // count
    return [value if i % stride == 0 else 0 for i, value in enumerate(a)]


class PhaseModel:
    """Small exact NTRU or two-mask GLWE model with canonical ciphertext residues."""

    def __init__(self, n, q, ntru):
        self.n, self.q, self.ntru = n, q, ntru
        self.secret = [1, 1, 0, 1] + [0] * (n - 4)
        self.second_secret = [0, 1, -1] + [0] * (n - 3)
        self.inverse = inverse(self.secret, q) if ntru else None

    def phase(self, ciphertext):
        if self.ntru:
            return multiply(ciphertext[0], self.secret, self.q)
        mask = add(multiply(ciphertext[0], self.secret, self.q),
                   multiply(ciphertext[1], self.second_secret, self.q), self.q)
        return add(ciphertext[2], scale(mask, -1, self.q), self.q)

    def automorphism(self, ciphertext, degree, error):
        """Ideal key switching under the original secret, with known phase error."""
        phase = add(transform(self.phase(ciphertext), degree, 0, self.q), error, self.q)
        if self.ntru:
            return [multiply(phase, self.inverse, self.q)]
        masks = [transform(a, degree, 0, self.q) for a in ciphertext[:2]]
        body = add(phase, multiply(masks[0], self.secret, self.q), self.q)
        body = add(body, multiply(masks[1], self.second_secret, self.q), self.q)
        return masks + [body]

    def halve(self, ciphertext):
        if self.q & 1:
            return [scale(a, pow(2, -1, self.q), self.q) for a in ciphertext], [0] * self.n
        parity = [[x & 1 for x in a] for a in ciphertext]
        # NTRU: f*p. GLWE: p_b - p_a0*s0 - p_a1*s1.
        return [[x // 2 for x in a] for a in ciphertext], self.phase(parity)


def check_projection(model, ciphertext, shared_depth, rng, errors):
    """Compare the ciphertext algorithm with direct coefficient/error selection.

    Events retain where an error was introduced, before any descendants exist.
    The expected phase uses only signed permutations and Pi, never another trace.
    """
    n, q = model.n, model.q
    levels = n.bit_length() - 1
    nodes = [(1, ciphertext)]
    events = []

    def next_error():
        return [rng.randrange(-2, 3) % q if errors else 0 for _ in range(n)]

    for k in range(1, shared_depth + 1):
        degree = (1 << k) + 1
        children = []
        for g, node in nodes:
            half, rounding = model.halve(node)
            error = next_error()
            children.extend([(g, half), (g * degree, model.automorphism(half, degree, error))])
            events.extend([(1 << (k - 1), g, scale(rounding, -1, q)),
                           (1 << k, g * degree, error)])
        nodes = children

    input_phase = model.phase(ciphertext)
    # Include the negative half of the negacyclic ring, selector strides and duplicates.
    indices = list(range(2 * n)) + [0, n // 4, n // 2, 3 * n // 4, 0]
    for index in indices:
        output = [[0] * n for _ in ciphertext]
        for g, node in nodes:
            output = [add(a, transform(b, 1, -g * index, q), q)
                      for a, b in zip(output, node)]
        expected = [input_phase[index % n] * (1 if index < n else -1) % q] + [0] * (n - 1)
        for count, g, error in events:
            expected = add(expected, retain(transform(error, 1, -g * index, q), count), q)
        for k in range(shared_depth + 1, levels + 1):
            half, rounding = model.halve(output)
            error = next_error()
            image = model.automorphism(half, (1 << k) + 1, error)
            output = [add(a, b, q) for a, b in zip(half, image)]
            expected = add(expected, scale(retain(rounding, 1 << (k - 1)), -1, q), q)
            expected = add(expected, retain(error, 1 << k), q)
        assert model.phase(output) == expected, (n, q, model.ntru, shared_depth, index)
    return len(indices)


def main():
    rng = Random(42)
    checked = 0
    for n in [8, 16, 32]:
        for q in [257, 1 << 8, 1 << 32, 1 << 64]:
            for ntru in [True, False]:
                model = PhaseModel(n, q, ntru)
                components = 1 if ntru else 3
                for errors in [False, True]:
                    # Dense nonzero tails, odd coefficients, wraparound and word boundaries.
                    inputs = [[[rng.randrange(1, q) for _ in range(n)] for _ in range(components)],
                              [[(q - 1 - i) % q for i in range(n)] for _ in range(components)]]
                    for ciphertext in inputs:
                        for depth in [0, 1, 2, 3]:
                            checked += check_projection(model, ciphertext, depth, rng, errors)
                if q == 257:
                    # Every message monomial is an independent noiseless oracle;
                    # this includes tails that invalidate zero-tail partial expansion.
                    for index in range(n):
                        phase = [int(i == index) for i in range(n)]
                        ciphertext = ([multiply(phase, model.inverse, q)] if ntru
                                      else [[0] * n, [0] * n, phase])
                        for depth in [1, 2]:
                            checked += check_projection(model, ciphertext, depth, rng, False)
    print(f"PASS: {checked} exact output-phase checks (NTT/native, NTRU/GLWE, shared depths 0..3)")


if __name__ == "__main__":
    main()
