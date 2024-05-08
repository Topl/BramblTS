/**
 * This file is used to extend the functionality of existing classes.
 *  considered dangerous to extend primary objects which might be extended in other libraries or frameworks
 *  we will attempt to only append brambl related classes and types and when required, we will add the prefix b to primary ts objects
 */

/// experimental extensions via typescript global module augmentation

declare global {
  interface Number {
    /**
     * Returns the number as a string.
     */
    bramblTestingOverride(): String;
    /**
     * Converts a number to a Uint8Array.
     */
    toUint8Array(): Uint8Array;
  }
  interface Uint8Array {
    /**
     * Converts a Uint8Array to a number.
     */
    toNumber(): number;
  }
}

Number.prototype.bramblTestingOverride = function () {
  return this.toString() + ' bramblTestingOverride';
};

Number.prototype.toUint8Array = function () {
  let arr = new Uint8Array(8);
  let num = this;

  for (let i = 0; i < 8; i++) {
    arr[i] = num % 256;
    num = Math.floor(num / 256);
  }

  return arr;
};

Uint8Array.prototype.toNumber = function () {
  let num = 0;

  for (let i = 7; i >= 0; i--) {
    num = num * 256 + this[i];
  }

  return num;
};
