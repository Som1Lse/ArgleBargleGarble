#!/usr/bin/env python3

import re
import time
import secrets
import hashlib
import statistics

from typing import Any, NamedTuple


class NotGate(NamedTuple):
    a: int


class AndGate(NamedTuple):
    a: int
    b: int


class XorGate(NamedTuple):
    a: int
    b: int


Gate = NotGate | AndGate | XorGate


class Circuit(NamedTuple):
    input_bits: list[int]
    gates: list[Gate]
    outputs: list[list[int]]


def parse_bristol_circuit(fn: str, new_format=True):
    with open(fn, "r") as file:
        it = iter(re.sub(r"\s+", " ", file.read()).strip().split(" "))

        def next_int():
            r = int(next(it))
            if r < 0:
                raise RuntimeError("Invalid integer in circuit")

            return r

        num_gates = next_int()
        num_wires = next_int()

        if new_format:
            input_bits = [next_int() for _ in range(next_int())]
            output_bits = [next_int() for _ in range(next_int())]
        else:
            input_bits = [next_int()]
            x = next_int()
            if x:
                input_bits.append(x)

            output_bits = [next_int()]

        num_inputs = sum(input_bits)

        wire_indices = list(range(num_inputs)) + num_gates * [-1]

        if num_gates + num_inputs != num_wires:
            raise RuntimeError("Invalid number of wires in circuit.")

        gates: list[Gate] = []

        for i in range(num_gates):
            num_in = next_int()
            if next_int() != 1:
                raise RuntimeError("Expected one output wire in circuit.")

            in_wires = [wire_indices[next_int()] for _ in range(num_in)]

            if any(a == -1 for a in in_wires):
                raise RuntimeError("Invalid gate input in circuit.")

            out_wire = next_int()
            if wire_indices[out_wire] != -1:
                raise RuntimeError("Reused wire in circuit.")

            match next(it):
                case "INV" | "NOT":
                    (a,) = in_wires
                    gates.append(NotGate(a))
                case "AND":
                    a, b = in_wires
                    gates.append(AndGate(a, b))
                case "XOR":
                    a, b = in_wires
                    gates.append(XorGate(a, b))
                case _:
                    # Note we do not support EQ, EQW or MAND gates.
                    raise RuntimeError("Invalid gate in circuit.")

            wire_indices[out_wire] = i + num_inputs

        # At this point we have written an index to each of the `wire_indices`,
        # so all of them are valid.

        outputs: list[list[int]] = []
        i = num_wires - sum(output_bits)
        for bits in output_bits:
            outputs.append(wire_indices[i : i + bits])
            i += bits

        if next(it, None) is not None:
            raise RuntimeError("Expected end of circuit.")

        return Circuit(
            input_bits=input_bits,
            gates=gates,
            outputs=outputs,
        )


def citcuit_stats(f: Circuit):
    not_gates = 0
    xor_gates = 0
    and_gates = 0

    for gate in f.gates:
        match gate:
            case NotGate(_):
                not_gates += 1
            case XorGate(_, _):
                xor_gates += 1
            case AndGate(_, _):
                and_gates += 1
            case _:
                assert False

    return not_gates, xor_gates, and_gates


def eval_circuit(f: Circuit, inputs: list[int]):
    """Evaluates the circuit `f` on inputs `x` and `y`. It mainly serves as a
    debugging function to make sure a circuit is written correctly.

    Corresponds to the 'ev' function."""

    values: list[bool] = []

    assert len(inputs) == len(f.input_bits)

    for x, bits in zip(inputs, f.input_bits):
        for i in range(bits):
            values.append(bool((x >> i) & 1))

    for gate in f.gates:
        match gate:
            case NotGate(a):
                values.append(not values[a])
            case XorGate(a, b):
                values.append(values[a] ^ values[b])
            case AndGate(a, b):
                values.append(values[a] and values[b])
            case _:
                assert False

    return [sum(values[j] << i for i, j in enumerate(x)) for x in f.outputs]


KEY_BYTES = 16


def set_lsb(k: bytes, p: bool):
    return bytes(((k[0] | 1 if p else k[0] & ~1),)) + k[1:]


def lsb(k: bytes):
    return bool(k[0] & 1)


def xor_bytes(a: bytes, *args: bytes):
    """Computes the XOR of two `bytes` objects."""

    for b in args:
        assert len(a) == len(b)

        a = bytes(x ^ y for x, y in zip(a, b))

    return a


GarbledKeys = tuple[bytes, bytes]


def sha_hash(keys: bytes | GarbledKeys, m: int) -> bytes:
    ks = (keys,) if isinstance(keys, bytes) else keys

    h = hashlib.sha256()

    for k in ks:
        h.update(k)

    h.update(m.to_bytes(16, "little"))

    return h.digest()[16:]


try:
    from Cryptodome.Cipher import AES

    def aes_hash_impl(keys: bytes | GarbledKeys, m: int) -> bytes:
        ks = (keys,) if isinstance(keys, bytes) else keys

        b = m.to_bytes(16, "little")

        return xor_bytes(*(AES.new(k, AES.MODE_ECB).encrypt(b) for k in ks))

    aes_hash = aes_hash_impl
except ImportError:

    def aes_hash_stub(keys: bytes | GarbledKeys, m: int) -> bytes:
        raise NotImplementedError()

    # This unholy incantation appeases the Pyright gods:
    # https://github.com/microsoft/pyright/issues/1871
    aes_hash = aes_hash_stub

try:
    import pyaesni

    def aesni_hash_impl(keys: bytes | GarbledKeys, m: int) -> bytes:
        b = m.to_bytes(16, "little")
        if isinstance(keys, bytes):
            return pyaesni.aesni1(keys, b)
        else:
            return pyaesni.aesni2(keys, b)

    aesni_hash = aesni_hash_impl
except ImportError:

    def aesni_hash_stub(keys: bytes | GarbledKeys, m: int) -> bytes:
        raise NotImplementedError()

    # As above.
    aesni_hash = aesni_hash_stub


# This is a function used to verify that the `pyaesni` C extension is correct.
def aes_aesni_hash(keys: bytes | GarbledKeys, m: int):
    r1 = aes_hash(keys, m)
    r2 = aesni_hash(keys, m)

    assert r1 == r2

    return r1


gen_hash = aesni_hash


def yao_encode(e: list[list[GarbledKeys]], x: list[int]):
    assert len(e) == len(x)

    return [[k[(x >> i) & 1] for i, k in enumerate(e)] for x, e in zip(x, e)]


def yao_decode(d: list[list[GarbledKeys]], Z: list[list[bytes]]):
    assert len(Z) == len(d)

    z: list[int] = []

    for dx, Zx in zip(d, Z):
        assert len(dx) == len(Zx)

        rng = enumerate(zip(dx, Zx))

        z.append(sum(dx.index(Zx) << i for i, (dx, Zx) in rng))

    return z


HalfGatesTable = tuple[bytes, bytes]


class HalfGatesAndGate(NamedTuple):
    a: int
    b: int

    gen_gate: bytes
    eval_gate: bytes


HalfGatesGate = XorGate | HalfGatesAndGate


class HalfGatesCircuit(NamedTuple):
    gates: list[HalfGatesGate]
    outputs: list[list[int]]


class HalfGates:
    @staticmethod
    def garble(f: Circuit):
        # Generate 16-byte `R` such that the low bit is always set.
        R = (secrets.randbits(8 * KEY_BYTES) | 1).to_bytes(KEY_BYTES, "little")

        assert lsb(R) == 1

        e: list[list[GarbledKeys]] = []
        keys: list[bytes] = []

        # Garble the `x` input wires.
        for bits in f.input_bits:
            ex: list[GarbledKeys] = []
            e.append(ex)
            for i in range(bits):
                k0 = secrets.token_bytes(KEY_BYTES)

                ex.append((k0, xor_bytes(k0, R)))
                keys.append(k0)

        F = HalfGatesCircuit([], [])

        base_index = len(keys)

        indices = list(range(len(keys)))

        i = 0

        # Garble the gate wires.
        for gate in f.gates:
            match gate:
                case NotGate(a):
                    keys.append(xor_bytes(keys[a], R))

                    indices.append(indices[a])
                case XorGate(a, b):
                    k0 = xor_bytes(keys[a], keys[b])

                    keys.append(k0)

                    indices.append(base_index + len(F.gates))

                    F.gates.append(XorGate(indices[a], indices[b]))
                case AndGate(a, b):
                    ka0 = keys[a]
                    kb0 = keys[b]

                    pa = lsb(ka0)
                    pb = lsb(kb0)

                    # Garble the generator half-gate `a and r`, knowing `r`.
                    ha0 = gen_hash(ka0, i)
                    ha1 = gen_hash(xor_bytes(ka0, R), i)

                    tg = xor_bytes(ha0, ha1)
                    tg = xor_bytes(tg, R) if pb else tg

                    wg0 = xor_bytes(ha0, tg) if pa else ha0

                    # Garble the evaluator half-gate `a and (r ^ b)`.
                    hb0 = gen_hash(kb0, i | 1)
                    hb1 = gen_hash(xor_bytes(kb0, R), i | 1)

                    xhb = xor_bytes(hb0, hb1)
                    te = xor_bytes(xhb, ka0)

                    we0 = xor_bytes(hb0, xhb) if pb else hb0

                    # Add to garbled circuit.
                    keys.append(xor_bytes(wg0, we0))

                    indices.append(base_index + len(F.gates))

                    F.gates.append(
                        HalfGatesAndGate(indices[a], indices[b], tg, te)
                    )

                    i += 2
                case _:
                    assert False

        for output in f.outputs:
            F.outputs.append([indices[i] for i in output])

        d = [
            [(keys[j], xor_bytes(keys[j], R)) for j in output]
            for output in f.outputs
        ]

        return F, e, d

    @staticmethod
    def evaluate(F: HalfGatesCircuit, X: list[list[bytes]]):
        keys = sum(X, [])

        i = 0

        for gate in F.gates:
            match gate:
                case XorGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    keys.append(xor_bytes(ka, kb))
                case HalfGatesAndGate(a, b, tg, te):
                    ka = keys[a]
                    kb = keys[b]

                    sa = lsb(ka)
                    sb = lsb(kb)

                    wg = gen_hash(ka, i)
                    wg = xor_bytes(wg, tg) if sa else wg

                    we = gen_hash(kb, i | 1)
                    we = xor_bytes(we, xor_bytes(te, ka)) if sb else we

                    keys.append(xor_bytes(wg, we))

                    i += 2
                case _:
                    assert False

        return [[keys[j] for j in output] for output in F.outputs]


class StandardAssumptionXorGate(NamedTuple):
    a: int
    b: int

    T: bytes


class StandardAssumptionAndGate(NamedTuple):
    a: int
    b: int

    T: tuple[bytes, bytes, bytes]


StandardAssumptionGate = StandardAssumptionXorGate | StandardAssumptionAndGate


class StandardAssumptionCircuit(NamedTuple):
    gates: list[StandardAssumptionGate]
    outputs: list[list[int]]


@staticmethod
def sa_gen_keys():
    # Generate 127 random bits for each key.
    k0 = secrets.randbits(8 * KEY_BYTES - 1) << 1
    k1 = secrets.randbits(8 * KEY_BYTES - 1) << 1

    # Generate permutation bits.
    if secrets.randbits(1):
        k0 |= 1
    else:
        k1 |= 1

    return (
        k0.to_bytes(KEY_BYTES, "little"),
        k1.to_bytes(KEY_BYTES, "little"),
    )


class StandardAssumption:
    @staticmethod
    def garble(f: Circuit):
        e: list[list[GarbledKeys]] = []
        keys: list[GarbledKeys] = []

        # Garble the `x` input wires.
        for bits in f.input_bits:
            ex: list[GarbledKeys] = []
            e.append(ex)
            for i in range(bits):
                k = sa_gen_keys()

                ex.append(k)
                keys.append(k)

        F = StandardAssumptionCircuit([], [])

        base_index = len(keys)

        indices = list(range(len(keys)))

        # Garble the gate wires.
        for gate in f.gates:
            i = len(F.gates) << 2

            match gate:
                case NotGate(a):
                    keys.append((keys[a][1], keys[a][0]))

                    indices.append(indices[a])
                case XorGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    pa = lsb(ka[0])
                    pb = lsb(kb[0])

                    pc = pa ^ pb

                    kap = (
                        gen_hash(ka[0], i | pa),
                        gen_hash(ka[1], i | (not pa)),
                    )

                    Rc = xor_bytes(kap[0], kap[1])

                    kb0p = gen_hash(kb[pb], i)
                    kb1p = xor_bytes(kb0p, Rc)

                    T = set_lsb(
                        xor_bytes(gen_hash(kb[not pb], i | 1), kb1p), False
                    )

                    kc0 = set_lsb(xor_bytes(kap[0], kb1p if pb else kb0p), pc)
                    kc1 = set_lsb(xor_bytes(kc0, Rc), not pc)

                    keys.append((kc0, kc1))
                    indices.append(base_index + len(F.gates))
                    F.gates.append(
                        StandardAssumptionXorGate(indices[a], indices[b], T)
                    )
                case AndGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    pa = lsb(ka[0])
                    pb = lsb(kb[0])

                    kc = (
                        gen_hash((ka[pa], kb[pb]), i),
                        secrets.token_bytes(KEY_BYTES),
                    )

                    # Note: This is different from the paper. The hash ALWAYS
                    # determines the permutation bit here instead of it being
                    # dependent on `pa and pb`.
                    # TODO: This is because the handling of the permutation bit is slightly different. Is this okay?
                    kc = (kc[0], set_lsb(kc[1], not lsb(kc[0])))

                    if pa and pb:
                        kc = (kc[1], kc[0])

                    T1 = xor_bytes(
                        gen_hash((ka[pa], kb[not pb]), i | 1),
                        kc[pa and not pb],
                    )

                    T2 = xor_bytes(
                        gen_hash((ka[not pa], kb[pb]), i | 2),
                        kc[not pa and pb],
                    )

                    T3 = xor_bytes(
                        gen_hash((ka[not pa], kb[not pb]), i | 3),
                        kc[not pa and not pb],
                    )

                    keys.append(kc)
                    indices.append(base_index + len(F.gates))
                    F.gates.append(
                        StandardAssumptionAndGate(
                            indices[a], indices[b], (T1, T2, T3)
                        )
                    )
                case _:
                    assert False

        for output in f.outputs:
            F.outputs.append([indices[i] for i in output])

        d = [[keys[j] for j in output] for output in f.outputs]

        return F, e, d

    @staticmethod
    def evaluate(F: StandardAssumptionCircuit, X: list[list[bytes]]):
        keys = sum(X, [])

        i = 0
        for gate in F.gates:
            match gate:
                case StandardAssumptionXorGate(a, b, T):
                    ka = keys[a]
                    kb = keys[b]

                    sa = lsb(ka)
                    sb = lsb(kb)

                    kc = xor_bytes(gen_hash(ka, i | sa), gen_hash(kb, i | sb))
                    kc = xor_bytes(kc, T) if sb else kc

                    sc = sa ^ sb

                    kc = set_lsb(kc, sc)

                    keys.append(kc)
                case StandardAssumptionAndGate(a, b, T):
                    ka = keys[a]
                    kb = keys[b]

                    j = lsb(ka) << 1 | lsb(kb)

                    h = gen_hash((ka, kb), i | j)

                    kc = xor_bytes(T[j - 1], h) if j else h

                    keys.append(kc)
                case _:
                    assert False

            i += 4

        return [[keys[j] for j in output] for output in F.outputs]


class StandardAssumptionXor3XorGate(NamedTuple):
    a: int
    b: int

    T: bytes


StandardAssumptionXor3Gate = (
    StandardAssumptionXor3XorGate | StandardAssumptionAndGate
)


class StandardAssumptionXor3Circuit(NamedTuple):
    gates: list[StandardAssumptionXor3Gate]
    outputs: list[list[int]]


class StandardAssumptionXor3:
    @staticmethod
    def garble(f: Circuit):
        e: list[list[GarbledKeys]] = []
        keys: list[GarbledKeys] = []

        # Garble the `x` input wires.
        for bits in f.input_bits:
            ex: list[GarbledKeys] = []
            e.append(ex)
            for i in range(bits):
                k = sa_gen_keys()

                ex.append(k)
                keys.append(k)

        F = StandardAssumptionXor3Circuit([], [])

        base_index = len(keys)

        indices = list(range(len(keys)))

        # Garble the gate wires.
        for gate in f.gates:
            i = len(F.gates) << 2

            match gate:
                case NotGate(a):
                    keys.append((keys[a][1], keys[a][0]))

                    indices.append(indices[a])
                case XorGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    pa = lsb(ka[0])
                    pb = lsb(kb[0])

                    pc = pa ^ pb

                    kap = (
                        gen_hash(ka[0], i | pa),
                        gen_hash(ka[1], i | (not pa)),
                    )

                    Rc = xor_bytes(kap[0], kap[1])

                    kb0p = kb[pb]
                    kb1p = xor_bytes(kb0p, Rc)

                    T = set_lsb(
                        xor_bytes(gen_hash(kb[not pb], i | 1), kb1p), False
                    )

                    kc0 = set_lsb(xor_bytes(kap[0], kb1p if pb else kb0p), pc)
                    kc1 = set_lsb(xor_bytes(kc0, Rc), not pc)

                    keys.append((kc0, kc1))
                    indices.append(base_index + len(F.gates))
                    F.gates.append(
                        StandardAssumptionXor3XorGate(
                            indices[a], indices[b], T
                        )
                    )
                case AndGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    pa = lsb(ka[0])
                    pb = lsb(kb[0])

                    kc = (
                        gen_hash((ka[pa], kb[pb]), i),
                        secrets.token_bytes(KEY_BYTES),
                    )

                    # Note: This is different from the paper. The hash ALWAYS
                    # determines the permutation bit here instead of it being
                    # dependent on `pa and pb`.
                    # TODO: This is because the handling of the permutation bit is slightly different. Is this okay?
                    kc = (kc[0], set_lsb(kc[1], not lsb(kc[0])))

                    if pa and pb:
                        kc = (kc[1], kc[0])

                    T1 = xor_bytes(
                        gen_hash((ka[pa], kb[not pb]), i | 1),
                        kc[pa and not pb],
                    )

                    T2 = xor_bytes(
                        gen_hash((ka[not pa], kb[pb]), i | 2),
                        kc[not pa and pb],
                    )

                    T3 = xor_bytes(
                        gen_hash((ka[not pa], kb[not pb]), i | 3),
                        kc[not pa and not pb],
                    )

                    keys.append(kc)
                    indices.append(base_index + len(F.gates))
                    F.gates.append(
                        StandardAssumptionAndGate(
                            indices[a], indices[b], (T1, T2, T3)
                        )
                    )
                case _:
                    assert False

        for output in f.outputs:
            F.outputs.append([indices[i] for i in output])

        d = [[keys[j] for j in output] for output in f.outputs]

        return F, e, d

    @staticmethod
    def evaluate(F: StandardAssumptionXor3Circuit, X: list[list[bytes]]):
        keys = sum(X, [])

        i = 0
        for gate in F.gates:
            match gate:
                case StandardAssumptionXor3XorGate(a, b, T):
                    ka = keys[a]
                    kb = keys[b]

                    sa = lsb(ka)
                    sb = lsb(kb)

                    kc = xor_bytes(
                        gen_hash(ka, i | sa),
                        gen_hash(kb, i | sb) if sb else kb,
                    )

                    kc = xor_bytes(kc, T) if sb else kc

                    sc = sa ^ sb

                    kc = set_lsb(kc, sc)

                    keys.append(kc)
                case StandardAssumptionAndGate(a, b, T):
                    ka = keys[a]
                    kb = keys[b]

                    j = lsb(ka) << 1 | lsb(kb)

                    h = gen_hash((ka, kb), i | j)

                    kc = xor_bytes(T[j - 1], h) if j else h

                    keys.append(kc)
                case _:
                    assert False

            i += 4

        return [[keys[j] for j in output] for output in F.outputs]


class StandardAssumptionGrr2AndGate(NamedTuple):
    a: int
    b: int

    T: tuple[bytes, bytes]
    t: tuple[bool, bool, bool, bool]


StandardAssumptionGrr2Gate = (
    StandardAssumptionXor3XorGate | StandardAssumptionGrr2AndGate
)


class StandardAssumptionGrr2Circuit(NamedTuple):
    gates: list[StandardAssumptionGrr2Gate]
    outputs: list[list[int]]


class StandardAssumptionGrr2:
    @staticmethod
    def garble(f: Circuit):
        e: list[list[GarbledKeys]] = []
        keys: list[GarbledKeys] = []

        # Garble the `x` input wires.
        for bits in f.input_bits:
            ex: list[GarbledKeys] = []
            e.append(ex)
            for i in range(bits):
                k = sa_gen_keys()

                ex.append(k)
                keys.append(k)

        F = StandardAssumptionGrr2Circuit([], [])

        base_index = len(keys)

        indices = list(range(len(keys)))

        # Garble the gate wires.
        for gate in f.gates:
            i = len(F.gates) << 2

            match gate:
                case NotGate(a):
                    keys.append((keys[a][1], keys[a][0]))

                    indices.append(indices[a])
                case XorGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    pa = lsb(ka[0])
                    pb = lsb(kb[0])

                    pc = pa ^ pb

                    kap = (
                        gen_hash(ka[0], i | pa),
                        gen_hash(ka[1], i | (not pa)),
                    )

                    Rc = xor_bytes(kap[0], kap[1])

                    kb0p = kb[pb]
                    kb1p = xor_bytes(kb0p, Rc)

                    T = set_lsb(
                        xor_bytes(gen_hash(kb[not pb], i | 1), kb1p), False
                    )

                    kc0 = set_lsb(xor_bytes(kap[0], kb1p if pb else kb0p), pc)
                    kc1 = set_lsb(xor_bytes(kc0, Rc), not pc)

                    keys.append((kc0, kc1))
                    indices.append(base_index + len(F.gates))
                    F.gates.append(
                        StandardAssumptionXor3XorGate(
                            indices[a], indices[b], T
                        )
                    )
                case AndGate(a, b):
                    ka = keys[a]
                    kb = keys[b]

                    pa = lsb(ka[0])
                    pb = lsb(kb[0])

                    K = (
                        gen_hash((ka[pa], kb[pb]), i),
                        gen_hash((ka[pa], kb[not pb]), i | 1),
                        gen_hash((ka[not pa], kb[pb]), i | 2),
                        gen_hash((ka[not pa], kb[not pb]), i | 3),
                    )

                    s = 3 ^ (pa << 1 | pb)

                    kc = (K[0], xor_bytes(K[1], K[2], K[3]))

                    if pa and pb:
                        kc = (kc[1], kc[0])

                    pc = bool(secrets.randbits(1))

                    kc = (set_lsb(kc[0], pc), set_lsb(kc[1], not pc))

                    T1 = set_lsb(xor_bytes(K[pa << 1], K[1 | pa << 1]), False)
                    T2 = set_lsb(xor_bytes(K[pb], K[2 | pb]), False)

                    t = tuple[bool, bool, bool, bool](
                        lsb(K[i]) ^ pc ^ (s == i) for i in range(4)
                    )

                    keys.append(kc)
                    indices.append(base_index + len(F.gates))
                    F.gates.append(
                        StandardAssumptionGrr2AndGate(
                            indices[a], indices[b], (T1, T2), t
                        )
                    )
                case _:
                    assert False

        for output in f.outputs:
            F.outputs.append([indices[i] for i in output])

        d = [[keys[j] for j in output] for output in f.outputs]

        return F, e, d

    @staticmethod
    def evaluate(F: StandardAssumptionCircuit, X: list[list[bytes]]):
        keys = sum(X, [])

        i = 0
        for gate in F.gates:
            match gate:
                case StandardAssumptionXor3XorGate(a, b, T):
                    ka = keys[a]
                    kb = keys[b]

                    sa = lsb(ka)
                    sb = lsb(kb)

                    kc = xor_bytes(
                        gen_hash(ka, i | sa),
                        gen_hash(kb, i | sb) if sb else kb,
                    )

                    kc = xor_bytes(kc, T) if sb else kc

                    sc = sa ^ sb

                    kc = set_lsb(kc, sc)

                    keys.append(kc)
                case StandardAssumptionGrr2AndGate(a, b, T, t):
                    ka = keys[a]
                    kb = keys[b]

                    sa = lsb(ka)
                    sb = lsb(kb)

                    j = sa << 1 | sb

                    kc = gen_hash((ka, kb), i | j)

                    pc = lsb(kc) ^ t[j]

                    if sb:
                        kc = xor_bytes(kc, T[0])

                    if sa:
                        kc = xor_bytes(kc, T[1])

                    kc = set_lsb(kc, pc)

                    keys.append(kc)
                case _:
                    assert False

            i += 4

        return [[keys[j] for j in output] for output in F.outputs]


# TODO: Related-key?


def run_test(scheme: Any, f: Circuit, n: int):
    garble_times: list[float] = []
    eval_times: list[float] = []

    for _ in range(n):
        t = time.perf_counter()

        F, e, d = scheme.garble(f)

        garble_times.append(time.perf_counter() - t)

        x = [secrets.randbits(b) for b in f.input_bits]

        X = yao_encode(e, x)

        t = time.perf_counter()

        Z = scheme.evaluate(F, X)

        eval_times.append(time.perf_counter() - t)

        z = yao_decode(d, Z)

        zp = eval_circuit(f, x)

        assert z == zp

    return (
        statistics.median(garble_times),
        statistics.median(eval_times),
    )


# TODO: Remove these test functions.
def test_circuit(n: str, f: Circuit, x: list[int]):
    z = eval_circuit(f, x)
    print(f"{n}{x} = {z}")

    schemes = {
        "HalfGates": HalfGates,
        "StandardAssumption": StandardAssumption,
        "StandardAssumptionXor3": StandardAssumptionXor3,
        "StandardAssumptionGrr2": StandardAssumptionGrr2,
    }

    for name, scheme in schemes.items():
        F, e, d = scheme.garble(f)
        X = yao_encode(e, x)
        Z = scheme.evaluate(F, X)
        zp = yao_decode(d, Z)

        if z != zp:
            print(f"{name} RESULT: {zp}")


import argparse


def main():
    argparser = argparse.ArgumentParser()

    argparser.add_argument(
        "circuits",
        type=str,
        nargs="*",
        help="List of circuits to run.",
    )

    argparser.add_argument(
        "--print-headers",
        "-p",
        action="store_const",
        default=False,
        const=True,
        help="Print the header line of a csv file",
    )

    argparser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=1,
        help="The number of iterations to run.",
    )

    args = argparser.parse_args()

    schemes = {
        "hg": HalfGates,
        "sa43": StandardAssumption,
        "sa33": StandardAssumptionXor3,
        "sa32": StandardAssumptionGrr2,
    }

    if args.print_headers:
        print(
            "circuit,not_gates,xor_gates,and_gates,xor_and_ratio",
            flush=True,
            end="",
        )

        for name in schemes:
            print(
                f",{name}_gtime,{name}_etime",
                flush=True,
                end="",
            )

        print()

    for name in args.circuits:
        fn = f"circuits/{name}.txt"

        f = parse_bristol_circuit(fn)
        not_gates, xor_gates, and_gates = citcuit_stats(f)

        print(
            f"{name},{not_gates},{xor_gates},{and_gates},"
            f"{xor_gates / and_gates:.6f}",
            flush=True,
            end="",
        )

        for scheme in schemes.values():
            gtime, etime = run_test(scheme, f, args.iterations)

            print(
                f",{gtime:.6f},{etime:.6f}",
                flush=True,
                end="",
            )

        print()


if __name__ == "__main__":
    main()
