import { BytesValue } from 'topl_common'; // Adjust import based on actual location
import { Buffer } from 'buffer';

/// A class that represents a sequence of bytes. uses [Buffer] under the hood as an extension of [Uint8Array]
export class ByteString {
  private _bytes: Buffer;

  constructor(bytes: Buffer) {
    this._bytes = bytes;
  }

  static fromUint8Array(bytes: Uint8Array): ByteString {
    return new ByteString(Buffer.from(bytes));
  }

  static fromList(bytes: number[]): ByteString {
    return new ByteString(Buffer.from(bytes));
  }

  static fromString(str: string): ByteString {
    return new ByteString(Buffer.from(str, 'utf8'));
  }

  get value(): Buffer {
    return this._bytes;
  }

  get bytes(): number[] {
    return Array.from(this._bytes);
  }

  get utf8String(): string {
    return this._bytes.toString('utf8');
  }

  get toBytesValue(): BytesValue {
    return new BytesValue({ value: this._bytes });
  }

  equals(other: ByteString): boolean {
    return this._bytes.equals(other._bytes);
  }

  hashCode(): number {
    // Simple hash code implementation; consider a more robust approach for production
    return this._bytes.reduce((acc, val) => acc + val, 0);
  }
}
