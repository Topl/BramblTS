class InitializationFailure implements Error {
  public message: string | undefined;
  public type: InitializationFailureType;

  constructor(type: InitializationFailureType, message?: string) {
    this.type = type;
    this.message = message;
  }
  name: string;
  stack?: string;

  static failedToCreateEntropy(context?: string): InitializationFailure {
    return new InitializationFailure(InitializationFailureType.FailedToCreateEntropy, context);
  }
}

enum InitializationFailureType {
  FailedToCreateEntropy,
}

export { InitializationFailure, InitializationFailureType };
