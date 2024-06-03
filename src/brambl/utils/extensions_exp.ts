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
    bramblTestingOverride?(): String;
    /**
     * Converts a number to a Uint8Array.
     */
    bToUint8Array?(): Uint8Array;
  }
  interface Uint8Array {
    /**
     * Converts a Uint8Array to a number.
     */
    bToNumber?(): number;

    /**
     * Checks if the Uint8Array is equal to another Uint8Array.
     */
    bEquals?(b: Uint8Array): boolean;
  }
  interface Array<T> {
    /**
     * Returns the sum of all elements in the array.
     */
    bSum?(): number;
  }
  interface String {
    /**
     * Converts a string to a Uint8Array.
     */
    bToUint8Array?(): Uint8Array;
  }
}

Number.prototype.bramblTestingOverride = function () {
  return this.toString() + ' bramblTestingOverride';
};

Number.prototype.bToUint8Array = function () {
  return numberToUint8Array4(this);
};

Uint8Array.prototype.bToNumber = function () {
  return this.reduce((accumulator, currentValue, currentIndex) => {
    return accumulator + currentValue * Math.pow(256, this.length - currentIndex - 1);
  }, 0);
};

Uint8Array.prototype.bEquals = function (b: Uint8Array) {
  if (this.length !== b.length) {
    return false;
  }

  for (let i = 0; i < this.length; i++) {
    if (this[i] !== b[i]) {
      return false;
    }
  }

  return true;
};

Array.prototype.bSum = function () {
  return this.reduce((a: number, b: number) => a + b, 0);
};

String.prototype.bToUint8Array = function(): Uint8Array {
  return Buffer.from(this);
};


/////// Helper functions ////////

///TODO: deprecated
function numberToUint8Array (num: number): Uint8Array {
  let buffer = new ArrayBuffer(4);
  let view = new DataView(buffer);
  view.setUint32(0, num, true); // true for little endian
  return new Uint8Array(buffer);
}

///TODO: deprecated
function numberToUint8Array2 (number: number): Uint8Array {
  // Determine the byte size needed for the number
  const byteSize = Math.max(Math.ceil(Math.log2(number + 1) / 8), 1);

  // Create an ArrayBuffer of appropriate size
  const buffer = new ArrayBuffer(byteSize);
  const view = new DataView(buffer);

  // Write the number to the buffer based on its byte size
  switch (byteSize) {
    case 1:
      view.setUint8(0, number);
      break;
    case 2:
      view.setUint16(0, number);
      break;
    case 4:
      view.setUint32(0, number);
      break;
    default:
      throw new Error('Number size not supported');
  }

  // Return a Uint8Array view of the buffer
  return new Uint8Array(buffer);
}

///TODO: deprecated
function numberToUint8Array3 (num) {
  let arr = new Uint8Array(8);

  for (let i = 0; i < 8; i++) {
    arr[i] = num % 256;
    num = Math.floor(num / 256);
  }

  return arr;
}

function numberToUint8Array4 (num: number): Uint8Array {
  // Calculate the number of bytes needed to represent the number
  const length = Math.ceil(Math.log2(num + 1) / 8);

  // Create a Uint8Array of the required length
  let arr = new Uint8Array(length);

  // Fill the Uint8Array with the bytes of the number
  for (let i = 0; i < length; i++) {
    arr[i] = num % 256;
    num = Math.floor(num / 256);
  }

  return arr;
}
