interface QuivrRunTimeError extends Error { }

/// A Validation error indicates that the evaluation of the proof failed for the given proposition within the provided context.
export class ValidationError implements QuivrRunTimeError {
    /// A message describing the Quivr error.
    public message: string;
    public name: string;
    public type: ValidationErrorType;

    constructor({ type, message, name }: { type: ValidationErrorType, message: string, name: string }) {
        this.type = type;
        this.message = message;
        this.name = name;
    }

    static evaluationAuthorizationFailure({ name, message }: { name: string, message: string, }): ValidationError {
        return new ValidationError(
            {
                type: ValidationErrorType.evaluationAuthorizationFailure,
                message: message,
                name: name,
            }
        );
    }

    static messageAuthorizationFailure({ name, message }: { name: string, message: string, }): ValidationError {
        return new ValidationError(
            {
                type: ValidationErrorType.messageAuthorizationFailure,
                message: message,
                name: name,
            }
        );
    }

    static lockedPropositionIsUnsatisfiable({ name, message }: { name: string, message: string, }): ValidationError {
        return new ValidationError(
            {
                type: ValidationErrorType.lockedPropositionIsUnsatisfiable,
                message: message,
                name: name,
            }
        );
    }

    static userProvidedInterfaceFailure({ name, message }: { name: string, message: string, }): ValidationError {
        return new ValidationError(
            {
                type: ValidationErrorType.userProvidedInterfaceFailure,
                message: message,
                name: name,
            }
        );
    }
    toString(): string {
        return `ContextError{message: ${this.message}, type: ${this.type}}`;
    }
}

enum ValidationErrorType {
    evaluationAuthorizationFailure,
    messageAuthorizationFailure,
    lockedPropositionIsUnsatisfiable,
    userProvidedInterfaceFailure
}


/// A Context error indicates that the Dynamic context failed to retrieve an instance of a requested member
export class ContextError implements QuivrRunTimeError {
    /// A message describing the Context error.
    public message: string;
    public name: string;
    public type: ContextErrorType;


    constructor({ type, message, name }: { type: ContextErrorType, message: string, name: string }) {
        this.type = type;
        this.name = name;
        this.message = message;
    }

    static failedToFindDigestVerifier({ name, message }: { name: string, message: string, }): ContextError {
        return new ContextError(
            {
                type: ContextErrorType.failedToFindDigestVerifier,
                message: message,
                name: name,
            }
        );
    }

    static failedToFindSignatureVerifier({ name, message }: { name: string, message: string, }): ContextError {
        return new ContextError(
            {
                type: ContextErrorType.failedToFindSignatureVerifier,
                message: message,
                name: name,
            }
        );;
    }

    static failedToFindDatum({ name, message }: { name: string, message: string, }): ContextError {
        return new ContextError(
            {
                type: ContextErrorType.failedToFindDatum,
                message: message,
                name: name,
            }
        );
    }

    static failedToFindInterface({ name, message }: { name: string, message: string, }): ContextError {
        return new ContextError(
            {
                type: ContextErrorType.failedToFindInterface,
                message: message,
                name: name,
            }
        );
    }

    toString(): string {
        return `ContextError{message: ${this.message}, type: ${this.type}}`;
    }
}

enum ContextErrorType {
    failedToFindDigestVerifier,
    failedToFindSignatureVerifier,
    failedToFindDatum,
    failedToFindInterface
}