import { QuivrResult } from '../common/quivr_result.js';
import { ContextlessValidation } from '../common/contextless_validation.js';

export class DigestVerifier<T> implements ContextlessValidation<T> {
    definedFunction: (t: T) => QuivrResult<T>;

    constructor(definedFunction: (t: T) => QuivrResult<T>) {
        this.definedFunction = definedFunction;
    }

    validate(t: T): QuivrResult<T> {
        return this.definedFunction(t);
    }
}