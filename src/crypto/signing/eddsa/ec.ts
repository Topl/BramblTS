/*
  Ed25519 is EdDSA instantiated with:
+-----------+-------------------------------------------------------+
| Parameter |                                                 Value |
+-----------+-------------------------------------------------------+
|     p     |     p of edwards25519 in [RFC7748] (i.e., 2^255 - 19) |
|     b     |                                                   256 |
|  encoding |    255-bit little-endian encoding of {0, 1, ..., p-1} |
|  of GF(p) |                                                       |
|    H(x)   |            SHA-512(dom2(phflag,context)||x) [RFC6234] |
|     c     |       base 2 logarithm of cofactor of edwards25519 in |
|           |                                   [RFC7748] (i.e., 3) |
|     n     |                                                   254 |
|     d     |  d of edwards25519 in [RFC7748] (i.e., -121665/121666 |
|           | = 370957059346694393431380835087545651895421138798432 |
|           |                           19016388785533085940283555) |
|     a     |                                                    -1 |
|     B     | (X(P),Y(P)) of edwards25519 in [RFC7748] (i.e., (1511 |
|           | 22213495354007725011514095885315114540126930418572060 |
|           | 46113283949847762202, 4631683569492647816942839400347 |
|           |      5163141307993866256225615783033603165251855960)) |
|     L     |             order of edwards25519 in [RFC7748] (i.e., |
|           |        2^252+27742317777372353535851937790883648493). |
|    PH(x)  |                       x (i.e., the identity function) |
+-----------+-------------------------------------------------------+
Table 1: Parameters of Ed25519
 */

/// AMS 2021: Supporting curve point operations for all EC crypto primitives in eddsa package
/// Directly ported from BouncyCastle implementation of Ed25519 RFC8032 https://tools.ietf.org/html/rfc8032
/// Licensing: https://www.bouncycastle.org/licence.html
/// Copyright (c) 2000 - 2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
/// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
/// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const M = BigInt(0xFFFFFFFF);

class EC {
  private _precompBaseTable: PointExt[];
  private _precompBase: Int32List;

  constructor() {
    const precompute = this._precompute();
    this._precompBaseTable = precompute.$1;
    this._precompBase = precompute.$2;
  }

  function mulAddTo256(x: Int32List, y: Int32List, zz: Int32List): number {
    const y_0 = BigInt(y[0]) & M;
    const y_1 = BigInt(y[1]) & M;
    const y_2 = BigInt(y[2]) & M;
    const y_3 = BigInt(y[3]) & M;
    const y_4 = BigInt(y[4]) & M;
    const y_5 = BigInt(y[5]) & M;
    const y_6 = BigInt(y[6]) & M;
    const y_7 = BigInt(y[7]) & M;

    let zc = BigInt(0);

    for (let i = 0; i < 8; i++) {
      let c = BigInt(0);
      const xi = BigInt(x[i]) & M;

      c += xi * y_0 + BigInt(zz[i + 0]) & M;
      zz[i + 0] = Number(c & M);
      c >>= 32n;

      c += xi * y_1 + BigInt(zz[i + 1]) & M;
      zz[i + 1] = Number(c & M);
      c >>= 32n;

      c += xi * y_2 + BigInt(zz[i + 2]) & M;
      zz[i + 2] = Number(c & M);
      c >>= 32n;

      c += xi * y_3 + BigInt(zz[i + 3]) & M;
      zz[i + 3] = Number(c & M);
      c >>= 32n;

      c += xi * y_4 + BigInt(zz[i + 4]) & M;
      zz[i + 4] = Number(c & M);
      c >>= 32n;

      c += xi * y_5 + BigInt(zz[i + 5]) & M;
      zz[i + 5] = Number(c & M);
      c >>= 32n;

      c += xi * y_6 + BigInt(zz[i + 6]) & M;
      zz[i + 6] = Number(c & M);
      c >>= 32n;

      c += xi * y_7 + BigInt(zz[i + 7]) & M;
      zz[i + 7] = Number(c & M);

      zc += c + BigInt(zz[i + 8]) & M;
      zz[i + 8] = Number(zc & M);
      zc >>= 32n;
    }

    return Number(zc);
  }

  function gte256(x: Int32List, y: Int32List): boolean {
    const MIN_VALUE = 0x80000000; // Int32.MIN_VALUE in Dart

    for (let i = 7; i >= 0; i--) {
        const xi = x[i] ^ MIN_VALUE; // Casting to 'any' for bitwise operations
        const yi = y[i] ^ MIN_VALUE; // Casting to 'any' for bitwise operations

        if (xi < yi) return false;
        if (xi > yi) return true;
    }

    return true;
  }

  function cmov(len: number, mask: number, x: Int32List, xOff: number, z: Int32List, zOff: number): void {
    let maskv = mask;
    maskv = -(maskv & 1);

    for (let i = 0; i < len; i++) {
        let zi = z[zOff + i];
        const diff = zi ^ x[xOff + i];
        zi ^= diff & maskv;
        z[zOff + i] = zi;
    }
  }

  function cadd(len: number, mask: number, x: Int32List, y: Int32List, z: Int32List): number {
    const m = -(mask & 1) & Number(M);
    let c = 0;

    for (let i = 0; i < len; i++) {
        c += (x[i] & Number(M)) + (y[i] & m);
        z[i] = c & Number(M);
        c >>>= 32;
    }

    return c;
  }
  
  function shiftDownBit(len: number, z: Int32List, c: number): number {
    let i = len;
    let cv = c;

    while (--i >= 0) {
        const next = z[i];
        z[i] = ((next >>> 1) | (cv << 31)) >>> 0;
        cv = next;
    }

    return (cv << 31) >>> 0;
  }

  function shuffle2(x: number): number {
    let t = 0;
    let xv = x;

    t = (xv ^ (xv >>> 7)) & 0x00aa00aa;
    xv ^= (t ^ (t << 7));

    t = (xv ^ (xv >>> 14)) & 0x0000cccc;
    xv ^= (t ^ (t << 14));

    t = (xv ^ (xv >>> 4)) & 0x00f000f0;
    xv ^= (t ^ (t << 4));

    t = (xv ^ (xv >>> 8)) & 0x0000ff00;
    xv ^= (t ^ (t << 8));

    return xv >>> 0;
  }

  function areAllZeroes(buf: Uint32List, off: number, len: number): boolean {
    let bits = 0;

    for (let i = 0; i < len; i++) {
        bits |= buf[off + i];
    }

    return bits === 0;
  }

  function calculateS(r: Uint8Array, k: Uint8Array, s: Uint8Array): Uint8Array {
    const t = new Int32Array(SCALAR_INTS * 2);
    decodeScalar(r, 0, t);
    const u = new Int32Array(SCALAR_INTS * 2);
    decodeScalar(k, 0, u);
    const v = new Int32Array(SCALAR_INTS * 2);
    decodeScalar(s, 0, v);
    mulAddTo256(u, v, t);
    const result = new Uint8Array(SCALAR_BYTES * 2);
    for (let i = 0; i < t.length; i++) {
        encode32(t[i], result, i * 4);
    }
    return reduceScalar(result);
  }

  function checkContextVar(ctx: Uint8Array, phflag: number): boolean {
    return (ctx.length === 0 && phflag === 0x00) || (ctx.length > 0 && ctx.length < 256);
  }

  function checkPointVar(p: Uint8Array): boolean {
    const t = new Int32Array(8);
    decode32(p, 0, t, 0, 8);
    t[7] = t[7] & 0x7fffffff;
    return !gte256(t, P);
  }

  function checkScalarVar(s: Uint8Array): boolean {
    const t = new Int32Array(SCALAR_INTS);
    decodeScalar(s, 0, t);
    return !gte256(t, L);
  }

  /// Decodes a 24-bit integer from a byte array starting at the specified offset.
  function decode24(bs: Uint8Array, off: number): number {
    let n = bs[off] & 0xff;
    n |= (bs[off + 1] & 0xff) << 8;
    n |= (bs[off + 2] & 0xff) << 16;
    return n;
  }

  /// Decodes a 32-bit integer from the given byte array starting at the specified offset.
  function decode32v(bs: Uint8Array, off: number): number {
    let n = bs[off] & 0xff;
    n |= (bs[off + 1] & 0xff) << 8;
    n |= (bs[off + 2] & 0xff) << 16;
    n |= bs[off + 3] << 24;
    return n >>> 0;
  }

  function decode32(bs: Uint8Array, bsOff: number, n: Int32List, nOff: number, nLen: number): void {
    for (let i = 0; i < nLen; i++) {
        n[nOff + i] = decode32v(bs, bsOff + i * 4);
    }
  }

  function decodePointVar(p: Uint8Array, pOff: number, { negate, r }: { negate: boolean; r: PointExt; }): boolean {
    const py = new Uint8Array(p.subarray(pOff, pOff + POINT_BYTES));
    if (!checkPointVar(py)) return false;
    const x_0 = (py[POINT_BYTES - 1] & 0x80) >>> 7;
    py[POINT_BYTES - 1] = py[POINT_BYTES - 1] & 0x7f;
    x25519_field.decode(py, 0, r.y);
    const u = x25519_field.create();
    const v = x25519_field.create();
    x25519_field.sqr(r.y, u);
    x25519_field.mul2(C_d, u, v);
    x25519_field.subOne(u);
    x25519_field.addOne1(v);
    if (!x25519_field.sqrtRatioVar(u, v, r.x)) return false;
    x25519_field.normalize(r.x);
    if (x_0 === 1 && x25519_field.isZeroVar(r.x)) return false;
    if (negate !== (x_0 !== (r.x[0] & 1))) x25519_field.negate(r.x, r.x);
    pointExtendXY(r);
    return true;
  }

}

const POINT_BYTES = 32;
const SCALAR_INTS = 8;
const SCALAR_BYTES = SCALAR_INTS * 4;
const PREHASH_SIZE = 64;