export class EncodingError extends Error {}

export class InvalidChecksum extends EncodingError {}

export class InvalidInputString extends EncodingError {}

export const uint8ArrayToBigInt = (uint8Array: Uint8Array) => {
    return BigInt("0x" + Array.from(uint8Array).map(byte => byte.toString(16).padStart(2, "0")).join(""));
}