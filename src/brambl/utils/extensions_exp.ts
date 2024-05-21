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
    bToUint8Array(): Uint8Array;
  }
  interface Uint8Array {
    /**
     * Converts a Uint8Array to a number.
     */
    bToNumber(): number;
  }
  interface Array<T> {
    /**
     * Returns the sum of all elements in the array.
     */
    bSum(): number;  

  }

}


Number.prototype.bramblTestingOverride = function () {
  return this.toString() + ' bramblTestingOverride';
};

Number.prototype.bToUint8Array = function () {
  let arr = new Uint8Array(8);
  let num = this;

  for (let i = 0; i < 8; i++) {
    arr[i] = num % 256;
    num = Math.floor(num / 256);
  }

  return arr;
};

Uint8Array.prototype.bToNumber = function () {
  let num = 0;

  for (let i = 7; i >= 0; i--) {
    num = num * 256 + this[i];
  }

  return num;
};


Array.prototype.bSum = function() {
  return this.reduce((a: number, b: number) => a + b, 0);
}