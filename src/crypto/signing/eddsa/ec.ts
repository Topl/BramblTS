/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-constant-condition */
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

export class EC {
  private _precompBaseTable: PointExt[];
  private _precompBase: Int32List;

  constructor() {
    const precompute = this._precompute();
    this._precompBaseTable = precompute[0];
    this._precompBase = precompute[1];
  }

  mulAddTo256(x: Int32List, y: Int32List, zz: Int32List): number {
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

  gte256(x: Int32List, y: Int32List): boolean {
    const MIN_VALUE = 0x80000000; // Int32.MIN_VALUE in Dart

    for (let i = 7; i >= 0; i--) {
        const xi = x[i] ^ MIN_VALUE; // Casting to 'any' for bitwise operations
        const yi = y[i] ^ MIN_VALUE; // Casting to 'any' for bitwise operations

        if (xi < yi) return false;
        if (xi > yi) return true;
    }

    return true;
  }

  cmov(len: number, mask: number, x: Int32List, xOff: number, z: Int32List, zOff: number): void {
    let maskv = mask;
    maskv = -(maskv & 1);

    for (let i = 0; i < len; i++) {
        let zi = z[zOff + i];
        const diff = zi ^ x[xOff + i];
        zi ^= diff & maskv;
        z[zOff + i] = zi;
    }
  }

  cadd(len: number, mask: number, x: Int32List, y: Int32List, z: Int32List): number {
    const m = -(mask & 1) & Number(M);
    let c = 0;

    for (let i = 0; i < len; i++) {
        c += (x[i] & Number(M)) + (y[i] & m);
        z[i] = c & Number(M);
        c >>>= 32;
    }

    return c;
  }
  
  shiftDownBit(len: number, z: Int32List, c: number): number {
    let i = len;
    let cv = c;

    while (--i >= 0) {
        const next = z[i];
        z[i] = ((next >>> 1) | (cv << 31)) >>> 0;
        cv = next;
    }

    return (cv << 31) >>> 0;
  }

  shuffle2(x: number): number {
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

  areAllZeroes(buf: Uint32List, off: number, len: number): boolean {
    let bits = 0;

    for (let i = 0; i < len; i++) {
        bits |= buf[off + i];
    }

    return bits === 0;
  }

  calculateS(r: Uint8Array, k: Uint8Array, s: Uint8Array): Uint8Array {
    const t = new Int32Array(SCALAR_INTS * 2);
    this.decodeScalar(r, 0, t);
    const u = new Int32Array(SCALAR_INTS * 2);
    this.decodeScalar(k, 0, u);
    const v = new Int32Array(SCALAR_INTS * 2);
    this.decodeScalar(s, 0, v);
    this.mulAddTo256(u, v, t);
    const result = new Uint8Array(SCALAR_BYTES * 2);
    for (let i = 0; i < t.length; i++) {
        encode32(t[i], result, i * 4);
    }
    return this.reduceScalar(result);
  }

  checkContextVar(ctx: Uint8Array, phflag: number): boolean {
    return (ctx.length === 0 && phflag === 0x00) || (ctx.length > 0 && ctx.length < 256);
  }

  checkPointVar(p: Uint8Array): boolean {
    const t = new Int32Array(8);
    this.decode32(p, 0, t, 0, 8);
    t[7] = t[7] & 0x7fffffff;
    return !this.gte256(t, P);
  }

  checkScalarVar(s: Uint8Array): boolean {
    const t = new Int32Array(SCALAR_INTS);
    this.decodeScalar(s, 0, t);
    return !this.gte256(t, L);
  }

  /// Decodes a 24-bit integer from a byte array starting at the specified offset.
  decode24(bs: Uint8Array, off: number): number {
    let n = bs[off] & 0xff;
    n |= (bs[off + 1] & 0xff) << 8;
    n |= (bs[off + 2] & 0xff) << 16;
    return n;
  }

  /// Decodes a 32-bit integer from the given byte array starting at the specified offset.
  decode32v(bs: Uint8Array, off: number): number {
    let n = bs[off] & 0xff;
    n |= (bs[off + 1] & 0xff) << 8;
    n |= (bs[off + 2] & 0xff) << 16;
    n |= bs[off + 3] << 24;
    return n >>> 0;
  }

  decode32(bs: Uint8Array, bsOff: number, n: Int32List, nOff: number, nLen: number): void {
    for (let i = 0; i < nLen; i++) {
        n[nOff + i] = this.decode32v(bs, bsOff + i * 4);
    }
  }

  decodePointVar(p: Uint8Array, pOff: number, { negate, r }: { negate: boolean; r: PointExt; }): boolean {
    const py = new Uint8Array(p.subarray(pOff, pOff + POINT_BYTES));
    if (!this.checkPointVar(py)) return false;
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
    this.pointExtendXY(r);
    return true;
  }

  decodeScalar(k: Uint8Array, kOff: number, n: Int32Array): void {
    this.decode32(k, kOff, n, 0, SCALAR_INTS);
  }

  encode24(n: number, bs: Uint8Array, off: number): void {
    bs[off] = n & 0xFF;
    bs[off + 1] = (n >>> 8) & 0xFF;
    bs[off + 2] = (n >>> 16) & 0xFF;
  }

  encode32(n: number, bs: Uint8Array, off: number): void {
    bs[off] = n & 0xFF;
    bs[off + 1] = (n >>> 8) & 0xFF;
    bs[off + 2] = (n >>> 16) & 0xFF;
    bs[off + 3] = (n >>> 24) & 0xFF;
  }

  encode56(n: bigint, bs: Uint8Array, off: number): void {
    this.encode32(Number(n & BigInt(0xFFFFFFFF)), bs, off);
    this.encode24(Number(n >> BigInt(32) & BigInt(0xFFFFFF)), bs, off + 4);
  }

  encodePoint(p: PointAccum, r: Uint8Array, rOff: number): void {
    const x = x25519_field.create();
    const y = x25519_field.create();
    x25519_field.inv(p.z, y);
    x25519_field.mul2(p.x, y, x);
    x25519_field.mul2(p.y, y, y);
    x25519_field.normalize(x);
    x25519_field.normalize(y);
    x25519_field.encode(y, r, rOff);
    r[rOff + POINT_BYTES - 1] = (r[rOff + POINT_BYTES - 1] | ((x[0] & 1) << 7)) & 0xFF;
  }

  getWNAF(n: Int32Array, width: number): Uint8Array {
    const t = new Int32Array(SCALAR_INTS * 2);
    let tPos = t.length;
    let c = 0;
    let i = SCALAR_INTS;
    while (--i >= 0) {
        const next = n[i];
        t[--tPos] = ((next >>> 16) | (c << 16)) | 0;
        c = next;
        t[--tPos] = c | 0;
    }
    const ws = new Uint8Array(256);
    const pow2 = 1 << width;
    const mask = pow2 - 1;
    const sign = pow2 >>> 1;
    let j = 0;
    let carry = 0;
    i = 0;
    while (i < t.length) {
        const word = t[i];
        while (j < 16) {
            const word16 = word >>> j;
            const bit = word16 & 1;
            if (bit === carry) {
                j += 1;
            } else {
                let digit = (word16 & mask) + carry;
                carry = digit & sign;
                digit -= (carry << 1);
                carry >>>= (width - 1);
                ws[(i << 4) + j] = digit & 0xFF;
                j += width;
            }
        }
        i += 1;
        j -= 16;
    }
    return ws;
  }

  scalarMultBaseYZ(k: Uint8Array, kOff: number, y: Int32List, z: Int32List): void {
    const n = new Uint8Array(SCALAR_BYTES);
    this.pruneScalar(k, kOff, n);
    const p = PointAccum.create();
    this.scalarMultBase(n, p);
    x25519_field.copy(p.y, 0, y, 0);
    x25519_field.copy(p.z, 0, z, 0);
  }

  pointAddVar1(negate: boolean, p: PointExt, r: PointAccum): void {
    const A = x25519_field.create();
    const B = x25519_field.create();
    const C = x25519_field.create();
    const D = x25519_field.create();
    const E = r.u;
    const F = x25519_field.create();
    const G = x25519_field.create();
    const H = r.v;

    let c: Int32Array;
    let d: Int32Array;
    let f: Int32Array;
    let g: Int32Array;

    if (negate) {
        c = D;
        d = C;
        f = G;
        g = F;
    } else {
        c = C;
        d = D;
        f = F;
        g = G;
    }

    x25519_field.apm(r.y, r.x, B, A);
    x25519_field.apm(p.y, p.x, d, c);
    x25519_field.mul2(A, C, A);
    x25519_field.mul2(B, D, B);
    x25519_field.mul2(r.u, r.v, C);
    x25519_field.mul2(C, p.t, C);
    x25519_field.mul2(C, C_d2, C);
    x25519_field.mul2(r.z, p.z, D);
    x25519_field.add(D, D, D);
    x25519_field.apm(B, A, H, E);
    x25519_field.apm(D, C, g, f);
    x25519_field.carry(g);
    x25519_field.mul2(E, F, r.x);
    x25519_field.mul2(G, H, r.y);
    x25519_field.mul2(F, G, r.z);
  }

  pointAddVar2(negate: boolean, p: PointExt, q: PointExt, r: PointExt): void {
    const A = x25519_field.create();
    const B = x25519_field.create();
    const C = x25519_field.create();
    const D = x25519_field.create();
    const E = x25519_field.create();
    const F = x25519_field.create();
    const G = x25519_field.create();
    const H = x25519_field.create();

    let c: Int32Array;
    let d: Int32Array;
    let f: Int32Array;
    let g: Int32Array;

    if (negate) {
        c = D;
        d = C;
        f = G;
        g = F;
    } else {
        c = C;
        d = D;
        f = F;
        g = G;
    }

    x25519_field.apm(p.y, p.x, B, A);
    x25519_field.apm(q.y, q.x, d, c);
    x25519_field.mul2(A, C, A);
    x25519_field.mul2(B, D, B);
    x25519_field.mul2(p.t, q.t, C);
    x25519_field.mul2(C, C_d2, C);
    x25519_field.mul2(p.z, q.z, D);
    x25519_field.add(D, D, D);
    x25519_field.apm(B, A, H, E);
    x25519_field.apm(D, C, g, f);
    x25519_field.carry(g);
    x25519_field.mul2(E, F, r.x);
    x25519_field.mul2(G, H, r.y);
    x25519_field.mul2(F, G, r.z);
    x25519_field.mul2(E, H, r.t);
  }

  pointAddPrecomp(p: PointPrecomp, r: PointAccum): void {
    const A = x25519_field.create();
    const B = x25519_field.create();
    const C = x25519_field.create();
    const E = r.u;
    const F = x25519_field.create();
    const G = x25519_field.create();
    const H = r.v;

    x25519_field.apm(r.y, r.x, B, A);
    x25519_field.mul2(A, p.ymxH, A);
    x25519_field.mul2(B, p.ypxH, B);
    x25519_field.mul2(r.u, r.v, C);
    x25519_field.mul2(C, p.xyd, C);
    x25519_field.apm(B, A, H, E);
    x25519_field.apm(r.z, C, G, F);
    x25519_field.carry(G);
    x25519_field.mul2(E, F, r.x);
    x25519_field.mul2(G, H, r.y);
    x25519_field.mul2(F, G, r.z);
  }

  pointCopyAccum(p: PointAccum): PointExt {
    const r = PointExt.create();
    x25519_field.copy(p.x, 0, r.x, 0);
    x25519_field.copy(p.y, 0, r.y, 0);
    x25519_field.copy(p.z, 0, r.z, 0);
    x25519_field.mul2(p.u, p.v, r.t);
    return r;
  }

  pointCopyExt(p: PointExt): PointExt {
    const r = PointExt.create();
    x25519_field.copy(p.x, 0, r.x, 0);
    x25519_field.copy(p.y, 0, r.y, 0);
    x25519_field.copy(p.z, 0, r.z, 0);
    x25519_field.copy(p.t, 0, r.t, 0);
    return r;
  }

  pointDouble(r: PointAccum) {
    const A = x25519_field.create();
    const B = x25519_field.create();
    const C = x25519_field.create();
    const E = r.u;
    const F = x25519_field.create();
    const G = x25519_field.create();
    const H = r.v;

    x25519_field.sqr(r.x, A);
    x25519_field.sqr(r.y, B);
    x25519_field.sqr(r.z, C);
    x25519_field.add(C, C, C);
    x25519_field.apm(A, B, H, G);
    x25519_field.add(r.x, r.y, E);
    x25519_field.sqr(E, E);
    x25519_field.sub(H, E, E);
    x25519_field.add(C, G, F);
    x25519_field.carry(F);
    x25519_field.mul2(E, F, r.x);
    x25519_field.mul2(G, H, r.y);
    x25519_field.mul2(F, G, r.z);
  }

  pointExtendXYAccum(p: PointAccum) {
    x25519_field.one(p.z);
    x25519_field.copy(p.x, 0, p.u, 0);
    x25519_field.copy(p.y, 0, p.v, 0);
  }

  pointExtendXY(p: PointExt): PointExt {
    x25519_field.one(p.z);
    x25519_field.mul2(p.x, p.y, p.t);
    return p;
  }

  pointLookup(block: number, index: number, p: PointPrecomp) {
    let off = block * PRECOMP_POINTS * 3 * x25519_field.SIZE;
    for (let i = 0; i < PRECOMP_POINTS; i++) {
        const mask = ((i ^ index) - 1) >> 31;
        this.cmov(x25519_field.SIZE, mask, this._precompBase, off, p.ypxH, 0);
        off += x25519_field.SIZE;
        this.cmov(x25519_field.SIZE, mask, this._precompBase, off, p.ymxH, 0);
        off += x25519_field.SIZE;
        this.cmov(x25519_field.SIZE, mask, this._precompBase, off, p.xyd, 0);
        off += x25519_field.SIZE;
    }
  }

  pointPrecompVar(p: PointExt, count: number): PointExt[] {
    const d = this.pointCopyExt(p);
    this.pointAddVar2(false, p, p, d);
    const table: PointExt[] = [this.pointCopyExt(p)];
    for (let i = 1; i < count; i++) {
        table.push(this.pointCopyExt(PointExt.create()));
        this.pointAddVar2(false, table[i - 1], d, table[i]);
    }
    return table;
  }

  pointSetNeutralAccum(p: PointAccum) {
    x25519_field.zero(p.x);
    x25519_field.one(p.y);
    x25519_field.one(p.z);
    x25519_field.zero(p.u);
    x25519_field.one(p.v);
  }

  pointSetNeutralExt(p: PointExt): PointExt {
    x25519_field.zero(p.x);
    x25519_field.one(p.y);
    x25519_field.one(p.z);
    x25519_field.zero(p.t);

    return p;
  }

  _precompute(): [PointExt[], Int32List] {
    // Precomputed table for the base point in verification ladder
    const b = this.pointExtendXY(this.pointCopyExt({ x: B_x.slice(), y: B_y.slice(), z: create(), t: create() }));
    const precompBaseTable = this.pointPrecompVar(b, 1 << (WNAF_WIDTH_BASE - 2));

    const p: PointAccum = {
        x: B_x.slice(),
        y: B_y.slice(),
        z: create(),
        u: create(),
        v: create(),
    };
    this.pointExtendXYAccum(p);

    const precompBase = new Int32Array(PRECOMP_BLOCKS * PRECOMP_POINTS * 3 * x25519_field.SIZE);
    let off = 0;

    for (let b = 0; b < PRECOMP_BLOCKS; b++) {
        const ds: PointExt[] = [];
        const sum = this.pointSetNeutralExt({ x: create(), y: create(), z: create(), t: create() });

        for (let t = 0; t < PRECOMP_TEETH; t++) {
            const q = this.pointCopyAccum(p);
            this.pointAddVar2(true, sum, q, sum);
            this.pointDouble(p);
            ds.push(this.pointCopyAccum(p));

            if (b + t !== PRECOMP_BLOCKS + PRECOMP_TEETH - 2) {
                for (let i = 1; i < PRECOMP_SPACING; i++) {
                    this.pointDouble(p);
                }
            }
        }

        const points: (PointExt | null)[] = Array.from({ length: PRECOMP_POINTS }, () => null);
        let k = 1;
        points[0] = sum;

        for (let t = 0; t < PRECOMP_TEETH - 1; t++) {
            const size = 1 << t;
            let j = 0;

            while (j < size) {
                points[k] = this.pointCopyExt(points[k - size]!);
                this.pointAddVar2(false, points[k - size]!, ds[t], points[k]!);
                j++;
                k++;
            }
        }

        for (let i = 0; i < PRECOMP_POINTS; i++) {
            const q = points[i]!;
            const x = create();
            const y = create();
            x25519_field.add(q.z, q.z, x);
            x25519_field.inv(x, y);
            x25519_field.mul2(q.x, y, x);
            x25519_field.mul2(q.y, y, y);

            const r = {
                ypxH: create(),
                ymxH: create(),
                xyd: create(),
            };

            x25519_field.apm(y, x, r.ypxH, r.ymxH);
            x25519_field.mul2(x, y, r.xyd);
            x25519_field.mul2(r.xyd, C_d4, r.xyd);

            x25519_field.normalize(r.ypxH);
            x25519_field.normalize(r.ymxH);

            precompBase.set(r.ypxH, off);
            off += x25519_field.SIZE;
            precompBase.set(r.ymxH, off);
            off += x25519_field.SIZE;
            precompBase.set(r.xyd, off);
            off += x25519_field.SIZE;
        }
    }

    return [precompBaseTable, precompBase];
  }

  pruneScalar(n: Uint8Array, nOff: number, r: Uint8Array): void {
    for (let i = 0; i < SCALAR_BYTES; i++) {
        r[i] = n[nOff + i];
    }
    r[0] = (r[0] & 0xf8) | 0;
    r[SCALAR_BYTES - 1] = (r[SCALAR_BYTES - 1] & 0x7f) | 0x40;
  }

  reduceScalar(n: Uint8Array): Uint8Array {
    const L0 = BigInt('0xfcf5d3ed');
    const L1 = BigInt('0x012631a6');
    const L2 = BigInt('0x079cd658');
    const L3 = BigInt('0xff9dea2f');
    const L4 = BigInt('0x000014df');

    const M28L = BigInt('0x0fffffff');
    const M32L = BigInt('0xffffffff');

    let x00 = BigInt(this.decode32v(n, 0)) & M32L;
    let x01 = BigInt(this.decode24(n, 4)) << BigInt(4) & M32L;
    let x02 = BigInt(this.decode32v(n, 7)) & M32L;
    let x03 = BigInt(this.decode24(n, 11)) << BigInt(4) & M32L;
    let x04 = BigInt(this.decode32v(n, 14)) & M32L;
    let x05 = BigInt(this.decode24(n, 18)) << BigInt(4) & M32L;
    let x06 = BigInt(this.decode32v(n, 21)) & M32L;
    let x07 = BigInt(this.decode24(n, 25)) << BigInt(4) & M32L;
    let x08 = BigInt(this.decode32v(n, 28)) & M32L;
    let x09 = BigInt(this.decode24(n, 32)) << BigInt(4) & M32L;
    let x10 = BigInt(this.decode32v(n, 35)) & M32L;
    let x11 = BigInt(this.decode24(n, 39)) << BigInt(4) & M32L;
    let x12 = BigInt(this.decode32v(n, 42)) & M32L;
    let x13 = BigInt(this.decode24(n, 46)) << BigInt(4) & M32L;
    let x14 = BigInt(this.decode32v(n, 49)) & M32L;
    let x15 = BigInt(this.decode24(n, 53)) << BigInt(4) & M32L;
    let x16 = BigInt(this.decode32v(n, 56)) & M32L;
    let x17 = BigInt(this.decode24(n, 60)) << BigInt(4) & M32L;
    const x18 = BigInt(n[63]) & BigInt(0xff);

    let t = BigInt(0);

    x09 -= x18 * L0;
    x10 -= x18 * L1;
    x11 -= x18 * L2;
    x12 -= x18 * L3;
    x13 -= x18 * L4;

    x17 += x16 >> BigInt(28);
    x16 &= M28L;

    x08 -= x17 * L0;
    x09 -= x17 * L1;
    x10 -= x17 * L2;
    x11 -= x17 * L3;
    x12 -= x17 * L4;

    x07 -= x16 * L0;
    x08 -= x16 * L1;
    x09 -= x16 * L2;
    x10 -= x16 * L3;
    x11 -= x16 * L4;

    x15 += x14 >> BigInt(28);
    x14 &= M28L;

    x06 -= x15 * L0;
    x07 -= x15 * L1;
    x08 -= x15 * L2;
    x09 -= x15 * L3;
    x10 -= x15 * L4;

    x05 -= x14 * L0;
    x06 -= x14 * L1;
    x07 -= x14 * L2;
    x08 -= x14 * L3;
    x09 -= x14 * L4;

    x13 += x12 >> BigInt(28);
    x12 &= M28L;

    x04 -= x13 * L0;
    x05 -= x13 * L1;
    x06 -= x13 * L2;
    x07 -= x13 * L3;
    x08 -= x13 * L4;

    x12 += x11 >> BigInt(28);
    x11 &= M28L;

    x03 -= x12 * L0;
    x04 -= x12 * L1;
    x05 -= x12 * L2;
    x06 -= x12 * L3;
    x07 -= x12 * L4;

    x11 += x10 >> BigInt(28);
    x10 &= M28L;

    x02 -= x11 * L0;
    x03 -= x11 * L1;
    x04 -= x11 * L2;
    x05 -= x11 * L3;
    x06 -= x11 * L4;

    x10 += x09 >> BigInt(28);
    x09 &= M28L;

    x01 -= x10 * L0;
    x02 -= x10 * L1;
    x03 -= x10 * L2;
    x04 -= x10 * L3;
    x05 -= x10 * L4;

    x08 += x07 >> BigInt(28);
    x07 &= M28L;

    x09 += x08 >> BigInt(28);
    x08 &= M28L;

    t = x08 >> BigInt(27);
    x09 += BigInt(t);

    x00 -= x09 * L0;
    x01 -= x09 * L1;
    x02 -= x09 * L2;
    x03 -= x09 * L3;
    x04 -= x09 * L4;

    x01 += x00 >> BigInt(28);
    x00 &= M28L;

    x02 += x01 >> BigInt(28);
    x01 &= M28L;

    x03 += x02 >> BigInt(28);
    x02 &= M28L;

    x04 += x03 >> BigInt(28);
    x03 &= M28L;

    x05 += x04 >> BigInt(28);
    x04 &= M28L;

    x06 += x05 >> BigInt(28);
    x05 &= M28L;

    x07 += x06 >> BigInt(28);
    x06 &= M28L;

    x08 += x07 >> BigInt(28);
    x07 &= M28L;

    const r = new Uint8Array(SCALAR_BYTES);
    this.encode56(x00 | (x01 << BigInt(28)), r, 0);
    this.encode56(x02 | (x03 << BigInt(28)), r, 7);
    this.encode56(x04 | (x05 << BigInt(28)), r, 14);
    this.encode56(x06 | (x07 << BigInt(28)), r, 21);
    this.encode32(Number(x08), r, 28);

    return r;
  }

  scalarMultBase(k: Uint8Array, r: PointAccum): void {
    this.pointSetNeutralAccum(r);

    const n = new Int32Array(SCALAR_INTS);
    this.decodeScalar(k, 0, n);

    // Recode the scalar into signed-digit form, then group comb bits in each block
    this.cadd(SCALAR_INTS, ~n[0] & 1, n, L, n);
    this.shiftDownBit(SCALAR_INTS, n, 1);

    for (let i = 0; i < SCALAR_INTS; i++) {
        n[i] = this.shuffle2(n[i]) >>> 0;
    }

    const p = PointPrecomp.create();
    let cOff = (PRECOMP_SPACING - 1) * PRECOMP_TEETH;

    while (true) {
        for (let b = 0; b < PRECOMP_BLOCKS; b++) {
            const w = n[b] >>> cOff;
            const sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
            const abs = (w ^ -sign) & PRECOMP_MASK;

            this.pointLookup(b, abs, p);

            x25519_field.cswap(sign, p.ypxH, p.ymxH);
            x25519_field.cnegate(sign, p.xyd);

            this.pointAddPrecomp(p, r);
        }

        cOff -= PRECOMP_TEETH;

        if (cOff < 0) {
            break;
        }

        this.pointDouble(r);
    }
  }

  createScalarMultBaseEncoded(s: Uint8Array): Uint8Array {
    const r = new Uint8Array(SCALAR_BYTES);
    this.scalarMultBaseEncoded(s, r, 0);
    return r;
  }

  scalarMultBaseEncoded(k: Uint8Array, r: Uint8Array, rOff: number): void {
    const p = PointAccum.create();
    this.scalarMultBase(k, p);
    this.encodePoint(p, r, rOff);
  }

  // This function performs scalar multiplication of a point on an elliptic curve using the Strauss algorithm with variable-time windowing.
  scalarMultStraussVar(nb: Int32Array, np: Int32Array, p: PointExt, r: PointAccum): void {
    // Set the window size to 5.
    const width = 5;

    // Compute the WNAF of the scalar values nb and np.
    const wsB = this.getWNAF(nb, WNAF_WIDTH_BASE).map((value) => value | 0);
    const wsP = this.getWNAF(np, width).map((value) => value | 0);

    // Compute a precomputed table of points based on the input point p.
    const tp = this.pointPrecompVar(p, 1 << (width - 2));

    // Initialize the result to the neutral element of the elliptic curve.
    this.pointSetNeutralAccum(r);

    // Start from the most significant bit and skip over any leading zero bits in both scalar values.
    let bit = 255;
    while (bit > 0 && (wsB[bit] | wsP[bit]) === 0) {
        bit -= 1;
    }

    while (true) {
        // Get the current bit of the scalar value nb.
        const wb = wsB[bit];

        // If the bit is non-zero,
        // perform a point addition operation using the corresponding point from the precomputed table.
        if (wb !== 0) {
            const sign = wb < 0 ? 1 : 0;
            const index = (sign !== 0 ? -wb : wb) >>> 1;
            this.pointAddVar1(sign !== 0, this._precompBaseTable[index], r);
        }

        // Get the current bit of the scalar value np.
        const wp = wsP[bit];

        // If the bit is non-zero,
        // perform a point addition operation using the corresponding point from the precomputed table.
        if (wp !== 0) {
            const sign = wp < 0 ? 1 : 0;
            const index = (sign !== 0 ? -wp : wp) >>> 1;
            this.pointAddVar1(sign !== 0, tp[index], r);
        }

        if (--bit < 0) break;
        this.pointDouble(r);
    }
  }
}

export const POINT_BYTES = 32;
export const SCALAR_INTS = 8;
export const SCALAR_BYTES = SCALAR_INTS * 4;
export const PREHASH_SIZE = 64;
export const PUBLIC_KEY_SIZE = POINT_BYTES;
export const SECRET_KEY_SIZE = 32;
export const SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES;
export const DOM2_PREFIX = "SigEd25519 no Ed25519 collisions";
const P = [0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff];
const L = [0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000, 0x00000000, 0x10000000];
const B_x = [
  0x0325d51a,
  0x018b5823,
  0x007b2c95,
  0x0304a92d,
  0x00d2598e,
  0x01d6dc5c,
  0x01388c7f,
  0x013fec0a,
  0x029e6b72,
  0x0042d26d
];

const B_y = [
  0x02666658,
  0x01999999,
  0x00666666,
  0x03333333,
  0x00cccccc,
  0x02666666,
  0x01999999,
  0x00666666,
  0x03333333,
  0x00cccccc
];

const C_d = [
  0x035978a3,
  0x02d37284,
  0x018ab75e,
  0x026a0a0e,
  0x0000e014,
  0x0379e898,
  0x01d01e5d,
  0x01e738cc,
  0x03715b7f,
  0x00a406d9
];

const C_d2 = [
  0x02b2f159,
  0x01a6e509,
  0x01156ebd,
  0x00d4141d,
  0x0001c029,
  0x02f3d130,
  0x03a03cbb,
  0x01ce7198,
  0x02e2b6ff,
  0x00480db3
];

const C_d4 = [
  0x0165e2b2,
  0x034dca13,
  0x002add7a,
  0x01a8283b,
  0x00038052,
  0x01e7a260,
  0x03407977,
  0x019ce331,
  0x01c56dff,
  0x00901b67
];

const WNAF_WIDTH_BASE = 7;
const PRECOMP_BLOCKS = 8;
const PRECOMP_TEETH = 4;
const PRECOMP_SPACING = 8;
const PRECOMP_POINTS = 1 << PRECOMP_TEETH - 1;
const PRECOMP_MASK = PRECOMP_POINTS - 1;
const M = BigInt(0xffffffff);

export class PointAccum {
  readonly x: Int32List;
  readonly y: Int32List;
  readonly z: Int32Array;
  readonly u: Int32Array;
  readonly v: Int32Array;

  constructor(x: Int32Array, y: Int32Array, z: Int32Array, u: Int32Array, v: Int32Array) {
    this.x = x;
    this.y = y;
    this.z = z;
    this.u = u;
    this.v = v;
  }

  static create(): PointAccum {
    return new PointAccum(
      new Int32Array(x25519_field.SIZE), 
      new Int32Array(x25519_field.SIZE), 
      new Int32Array(x25519_field.SIZE), 
      new Int32Array(x25519_field.SIZE), 
      new Int32Array(x25519_field.SIZE)
    );
  }
}

export class PointExt {
  readonly x: Int32List;
  readonly y: Int32List;
  readonly z: Int32Array;
  readonly t: Int32Array;

  constructor(x: Int32Array, y: Int32Array, z: Int32Array, t: Int32Array) {
    this.x = x;
    this.y = y;
    this.z = z;
    this.t = t;
  }

  static create(): PointExt {
    return new PointExt(
      new Int32Array(x25519_field.SIZE),
      new Int32Array(x25519_field.SIZE),
      new Int32Array(x25519_field.SIZE),
      new Int32Array(x25519_field.SIZE)
    );
  }
}

class PointPrecomp {
  readonly ypxH: Int32Array;
  readonly ymxH: Int32Array;
  readonly xyd: Int32Array;

  constructor(ypxH: Int32Array, ymxH: Int32Array, xyd: Int32Array) {
    this.ypxH = ypxH;
    this.ymxH = ymxH;
    this.xyd = xyd;
  }

  static create(): PointPrecomp {
    return new PointPrecomp(
      new Int32Array(x25519_field.SIZE),
      new Int32Array(x25519_field.SIZE),
      new Int32Array(x25519_field.SIZE)
    );
  }
}

function toByte(n: number): number {
  const buffer = new ArrayBuffer(1);
  const view = new DataView(buffer);
  view.setInt8(0, n);
  return view.getUint8(0);
}
