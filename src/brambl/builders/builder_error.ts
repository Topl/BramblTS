export class BuilderError implements Error {
    message: string | undefined;
    type: BuilderErrorType | undefined;
    exception: Error | undefined;
    name: string;
  
    constructor(message?: string, { type, exception }: { type?: BuilderErrorType; exception?: Error } = {}) {
      this.message = message;
      this.type = type;
      this.exception = exception;
      this.name = "BuilderError";
    }
  
    static inputBuilder(context?: string): BuilderError {
      return new BuilderError(context, { type: BuilderErrorType.inputBuilderError });
    }
  
    static outputBuilder(context?: string): BuilderError {
      return new BuilderError(context, { type: BuilderErrorType.outputBuilderError });
    }
  
    toString(): string {
      return `BuilderError{message: ${this.message}, type: ${this.type}, exception: ${this.exception}}`;
    }
  }
  
  enum BuilderErrorType {
    inputBuilderError,
    outputBuilderError,
  }