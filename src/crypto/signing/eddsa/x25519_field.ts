import bigInt, { BigInteger } from 'big-integer';

const SIZE = 10;
const M24 = 0x00ffffff;
const M25 = 0x01ffffff;
const M26 = 0x03ffffff;
const ROOT_NEG_ONE: number[] = [
  0x020ea0b0, 0x0386c9d2, 0x00478c4e, 0x0035697f, 0x005e8630, 0x01fbd7a7, 0x0340264f, 0x01f0b2b4, 0x00027e0e,
  0x00570649,
];

function create(): number[] {
  return new Array(SIZE).fill(0);
}

function isZero(x: number[]): number {
  let d = 0;
  for (let i = 0; i < SIZE; i++) {
    d |= x[i];
  }
  d = (d >>> 1) | (d & 1);
  return ((d - 1) >> 31) & 1;
}

function isZeroVar(x: number[]): boolean {
  return isZero(x) !== 0;
}

function mul2(x: Int32Array, y: Int32Array, z: Int32Array): void {
  const M26 = 0x3ffffffn; // example values; adjust accordingly
  const M25 = 0x1ffffffn; // example values; adjust accordingly

  let x0 = BigInt(x[0]);
  let y0 = BigInt(y[0]);
  let x1 = BigInt(x[1]);
  let y1 = BigInt(y[1]);
  let x2 = BigInt(x[2]);
  let y2 = BigInt(y[2]);
  let x3 = BigInt(x[3]);
  let y3 = BigInt(y[3]);
  let x4 = BigInt(x[4]);
  let y4 = BigInt(y[4]);
  const u0 = BigInt(x[5]);
  const v0 = BigInt(y[5]);
  const u1 = BigInt(x[6]);
  const v1 = BigInt(y[6]);
  const u2 = BigInt(x[7]);
  const v2 = BigInt(y[7]);
  const u3 = BigInt(x[8]);
  const v3 = BigInt(y[8]);
  const u4 = BigInt(x[9]);
  const v4 = BigInt(y[9]);
  // ... [same code structure with BigInts replacing Int64]

  // Example for conversion:
  // Dart: var a0 = Int64(x0) * y0;
  // TypeScript: let a0 = x0 * y0;

  // ... [rest of the function with BigInts]

  // When assigning to the Int32Array:
  // Dart: z[0] = (t.toInt32() & M26).toInt();
  // TypeScript: z[0] = Number(t & M26);
}
function sqr(x: number[], z: number[]): void {
  const x0 = bigInt(x[0]);
  // Partial implementation...
  let x1_2 = x[1] * 2;
  // ... rest of the conversion using bigInt arithmetic
}

// ... rest of your functions ...

function sqr2(x: number[], y: number[], z: number[]): void {
  const x0 = bigInt(x[0]);
  const x1 = bigInt(x[1]);
  // ... get other values similarly

  let x1_2 = x1.shiftLeft(1);
  // ... more computations using bigInt arithmetic

  const y0 = bigInt(y[0]);
  const y1 = bigInt(y[1]);
  // ... get other values similarly

  let y1_2 = y1.shiftLeft(1);
  // ... more computations using bigInt arithmetic

  // Convert the rest of the Dart code to TypeScript/bigInt
  // Make sure you use bigInt methods for operations, e.g., .add(), .multiply(), etc.
}

function powPm5d8(x: number[], rx2: number[], rz: number[]): void {
  // (250 1s) (1 0s) (1 1s)
  // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]
  const x2 = rx2;
  sqr(x, x2);
  mul2(x, x2, x2);
  const x3: number[] = [];
  sqr(x2, x3);
  mul2(x, x3, x3);
  const x5 = x3;
  sqr2(x3, 2, x5);
  mul2(x2, x5, x5);
  const x10: number[] = [];
  sqr2(x5, 5, x10);
  mul2(x5, x10, x10);
  const x15: number[] = [];
  sqr2(x10, 5, x15);
  mul2(x5, x15, x15);
  const x25 = x5;
  sqr2(x15, 10, x25);
  mul2(x10, x25, x25);
  const x50 = x10;
  sqr2(x25, 25, x50);
  mul2(x25, x50, x50);
  const x75 = x15;
  sqr2(x50, 25, x75);
  mul2(x25, x75, x75);
  const x125 = x25;
  sqr2(x75, 50, x125);
  mul2(x50, x125, x125);
  const x250 = x50;
  sqr2(x125, 125, x250);
  mul2(x125, x250, x250);
  const t: number[] = [];
  sqr2(x250, 2, t);
  mul2(t, x, rz);
}
