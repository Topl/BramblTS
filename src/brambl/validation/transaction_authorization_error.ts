import { ValidationError, type QuivrRuntimeError } from "@/quivr4s/quivr/runtime/quivr_runtime_error.js";

export abstract class TransactionAuthorizationError extends ValidationError {}

export class AuthorizationFailed extends TransactionAuthorizationError {
  errors: QuivrRuntimeError[];

  constructor(errors: QuivrRuntimeError[] = []) {
    super(null);
    this.errors = errors;
  }
}

export class Contextual extends TransactionAuthorizationError {
  error: QuivrRuntimeError;

  constructor(error: QuivrRuntimeError) {
    super(null);
    this.error = error;
  }
}

export class Permanent extends TransactionAuthorizationError {
  error: QuivrRuntimeError;

  constructor(error: QuivrRuntimeError) {
    super(null);
    this.error = error;
  }
}