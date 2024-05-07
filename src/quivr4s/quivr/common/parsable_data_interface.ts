import type { Either } from '@/common/functional/either.js';
import { Data } from 'topl_common';

/// Provides Digest verification for use in a Dynamic Context
export default class ParsableDataInterface {
  data: Data;

  constructor(data: Data) {
    this.data = data;
  }

  parse<E, T>(f: (data: Data) => Either<E, T>): Either<E, T> {
    return f(this.data);
  }
}
