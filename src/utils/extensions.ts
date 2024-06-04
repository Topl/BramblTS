export function fromLittleEndian(bytes: Uint8Array): bigint {
  let result = BigInt(0);
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

export function hexToUint8List(hex: string): Uint8Array {
  const hexString = hex.trim();
  const result = new Uint8Array(hexString.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return result;
}

export function uint8ListFromBytes(bytes: number[]): Uint8Array {
  return new Uint8Array(bytes);
}

export function bigIntToUint8Array(value: bigint): Uint8Array {
  const hexString = value.toString(16);
  const paddedHexString = hexString.length % 2 === 0 ? hexString : '0' + hexString;
  const byteArray = new Uint8Array(paddedHexString.length / 2);

  for (let i = 0; i < paddedHexString.length; i += 2) {
    byteArray[i / 2] = parseInt(paddedHexString.slice(i, i + 2), 16);
  }

  return byteArray;
}

export function padArray(array: Uint8Array, length: number): Uint8Array {
  const paddedArray = new Uint8Array(length);
  paddedArray.set(array, 0);
  return paddedArray;
}

export function equals(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false;
    }
  }

  return true;
}

export function getSublist(array: Uint8Array, start: number, end: number): Uint8Array {
  return array.slice(start, end);
}

export function toIntList(uint8Array: Uint8Array): number[] {
  return Array.from(uint8Array);
}
