/// class made to emulate some dart and scala extension methods, somehow feels like a meme..

/**
 * Checks if an object has a specific property.
 *
 * @param obj - The object to check.
 * @param prop - The property to check for.
 * @returns A boolean indicating whether the object has the specified property.
 */
export function hasProperty<T> (obj: T, prop: keyof T): boolean {
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

export function isNotNull<T> (value: T | null): boolean {
  return value !== null;
}

export function isNull<T> (value: T | null): boolean {
    return value === null;
  }


/**
 * Checks if any of the provided values are null.
 * @param values - The values to check.
 * @returns `true` if any of the values are null, `false` otherwise.
 */
  export function areAnyNull(...values: Array<any>): boolean {
    return values.some(value => value === null);
  }

/**
 * Checks if all of the provided values are not null.
 * @param values - The values to check.
 * @returns `true` if all of the values are not null, `false` otherwise.
 */
export function areAllNotNull(...values: Array<any>): boolean {
    return values.every(value => value !== null);
  }