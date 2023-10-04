import { Data } from './types.js';

/// Provides Digest verification for use in a Dynamic Context
export class ParsableDataInterface<T> {
  data: Data;

  constructor(data: Data) {
    this.data = data;
  }

  parse(f: (data: Data) => T): T {
    return f(this.data);
  }
}
