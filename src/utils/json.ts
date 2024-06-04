import { toIntList } from './extensions.js';

export class Json {
  static decodeUint8List(encoded: string): Uint8Array {
    const dynamicDecode: any[] = JSON.parse(encoded);
    const decoded = dynamicDecode.map((i) => (typeof i === 'number' ? i : 0)); // assuming non-numbers become 0
    return new Uint8Array(decoded);
  }

  static encodeUint8List(data: Uint8Array): string {
    const toEncode: number[] = toIntList(data);
    return JSON.stringify(toEncode);
  }
}
