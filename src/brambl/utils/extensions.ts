/// class made to emulate some dart and scala extension methods, somehow feels like a meme..

/**
 * Checks if an object has a specific property.
 *
 * @param obj - The object to check.
 * @param prop - The property to check for.
 * @returns A boolean indicating whether the object has the specified property.
 */
export function hasProperty<T>(obj: T, prop: keyof T): boolean {
  return obj.hasOwnProperty(prop);
}

/**
 * Checks if a value is not null or undefined. shorthand to improve readability
 *
 * @param value - The value to check.
 * @returns `true` if the value is not null or undefined, `false` otherwise.
 */
export function has(value: any): boolean {
  return isNotNull(value);
}

export function isNotNull<T>(value: T | null): boolean {
  return value !== null;
}

export function isNull<T>(value: T | null): boolean {
  return value === null;
}

/**
 * Checks if any of the provided values are null.
 * @param values - The values to check.
 * @returns `true` if any of the values are null, `false` otherwise.
 */
export function areAnyNull(...values: Array<any>): boolean {
  return values.some((value) => value === null);
}

/**
 * Checks if all of the provided values are not null.
 * @param values - The values to check.
 * @returns `true` if all of the values are not null, `false` otherwise.
 */
export function areAllNotNull(...values: Array<any>): boolean {
  return values.every((value) => value !== null);
}

export class Uint8ArrayUtils {
  static add(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  static equals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  // TODO figure out which version to use, buffer not available in all environments
  static toBigInt(a: Uint8Array): bigint {
    return BigInt('0x' + Buffer.from(a).toString('hex'));
  }

  static toBigInt2(a: Uint8Array): bigint {
    const hex = Array.from(a)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return BigInt(`0x${hex}`);
  }
}

class bigIntExtensions {
  // WARNING: does not handle negatives!
  static toUint8Array(n: bigint): Uint8Array {
    const hex = n.toString(16);
    const len = hex.length;
    const u8 = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
      u8[i / 2] = parseInt(hex.substring(i, 2), 16);
    }
    return u8;
  }
}
