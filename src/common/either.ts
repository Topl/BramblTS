export interface Option<T> {
  isDefined: boolean;
  getOrElse(defaultValue: T): T;
  getOrThrow(exception?: Error): T;
  forEach(f: (t: T) => void): void;
  map<U>(f: (t: T) => U): Option<U>;
  flatMap<U>(f: (t: T) => Option<U>): Option<U>;
  fold<U>(onDefined: (t: T) => U, onUndefined: () => U): U;
}

export class Some<T> implements Option<T> {
  constructor(public readonly value: T) {}

  get isDefined(): boolean {
    return true;
  }

  getOrElse(defaultValue: T): T {
    return this.value;
  }

  getOrThrow(): T {
    return this.value;
  }

  map<U>(f: (t: T) => U): Option<U> {
    return new Some(f(this.value));
  }

  forEach(f: (t: T) => void): void {
    f(this.value);
  }

  flatMap<U>(f: (t: T) => Option<U>): Option<U> {
    return f(this.value);
  }

  fold<U>(onDefined: (t: T) => U, onUndefined: () => U): U {
    return onDefined(this.value);
  }
}

export class None<T> implements Option<T> {
  get isDefined(): boolean {
    return false;
  }

  getOrElse(defaultValue: T): T {
    return defaultValue;
  }

  getOrThrow(exception: Error = new Error('Value is not defined.')): T {
    throw exception;
  }

  map<U>(_f: (t: T) => U): Option<U> {
    return new None<U>();
  }

  forEach(_f: (t: T) => void): void {}

  flatMap<U>(_f: (t: T) => Option<U>): Option<U> {
    return new None<U>();
  }

  fold<U>(_onDefined: (t: T) => U, onUndefined: () => U): U {
    return onUndefined();
  }
}

export type Either<L, R> = { kind: 'Left'; value: L } | { kind: 'Right'; value: R };

export class EitherException extends Error {
  constructor(public readonly message: string) {
    super(message);
  }

  static rightIsUndefined() {
    return new EitherException('Right value is undefined!');
  }

  toString(): string {
    return `EitherException{message: ${this.message}}`;
  }
}

export class Unit {}
