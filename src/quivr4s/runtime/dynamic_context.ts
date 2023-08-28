interface Datum {
    [key: string]: any;
}

interface ParsableDataInterface {
    parse(data: any): Datum;
}

interface SignatureVerifier {
    validate(verification: SignatureVerification): QuivrResult<SignatureVerification>;
}

interface DigestVerifier {
    validate(verification: DigestVerification): QuivrResult<DigestVerification>;
}

interface SignableBytes {
    [key: string]: any;
}

interface QuivrResult<T> {
    isLeft: boolean;
    left: any;
    right: T;
}

interface DigestVerification {
    [key: string]: any;
}

interface SignatureVerification {
    [key: string]: any;
}

interface Data {
    value: any;
    toBigInt: number;
}

enum ContextError {
    failedToFindDigestVerifier,
    failedToFindSignatureVerifier,
    failedToFindInterface,
}

export class DynamicContext {
    datum: Map<string, Datum | null>;
    interfaces: Map<string, ParsableDataInterface>;
    signingRoutines: Map<string, SignatureVerifier>;
    hashingRoutines: Map<string, DigestVerifier>;
    signableBytes: SignableBytes;
    currentTick: number;
    heightOf?: (arg0: string) => number | null;

    constructor(
        datum: Map<string, Datum | null>,
        interfaces: Map<string, ParsableDataInterface>,
        signingRoutines: Map<string, SignatureVerifier>,
        hashingRoutines: Map<string, DigestVerifier>,
        signableBytes: SignableBytes,
        currentTick: number,
        heightOf?: (arg0: string) => number | null
    ) {
        this.datum = datum;
        this.interfaces = interfaces;
        this.signingRoutines = signingRoutines;
        this.hashingRoutines = hashingRoutines;
        this.signableBytes = signableBytes;
        this.currentTick = currentTick;
        this.heightOf = heightOf;
    }

    digestVerify(routine: string, verification: DigestVerification): QuivrResult<DigestVerification> {
        const verifier = this.hashingRoutines.has(routine) ? this.hashingRoutines.get(routine) : null;

        if (verifier === null) return QuivrResult.left(ContextError.failedToFindDigestVerifier);

        const result = verifier.validate(verification) as QuivrResult<DigestVerification>;
        if (result.isLeft) return result;

        return QuivrResult.right(result.right);
    }

    signatureVerify(routine: string, verification: SignatureVerification): QuivrResult<SignatureVerification> {
        const verifier = this.signingRoutines.has(routine) ? this.signingRoutines.get(routine) : null;

        if (verifier === null) return QuivrResult.left(ContextError.failedToFindSignatureVerifier);

        const result = verifier.validate(verification) as QuivrResult<SignatureVerification>;
        if (result.isLeft) return result;

        return QuivrResult.right(result.right);
    }

    useInterface(label: string): QuivrResult<Data> {
        const interfaceObj = this.interfaces.has(label) ? this.interfaces.get(label) : null;

        if (interfaceObj === null) return QuivrResult.left(ContextError.failedToFindInterface);

        return QuivrResult.right(interfaceObj.parse((data: any) => data));
    }

    exactMatch(label: string, compareTo: number[]): boolean {
        const result = this.useInterface(label);

        if (result.isLeft) return false;

        return JSON.stringify(result.right?.value) === JSON.stringify(compareTo);
    }

    lessThan(label: string, compareTo: number): boolean {
        const result = this.useInterface(label);

        if (result.isLeft) return false;

        return result.right!.value.toBigInt() <= compareTo;
    }

    greaterThan(label: string, compareTo: number): boolean {
        const result = this.useInterface(label);

        if (result.isLeft) return false;

        return result.right!.value.toBigInt() >= compareTo;
    }

    equalTo(label: string, compareTo: number): boolean {
        const result = this.useInterface(label);

        if (result.isLeft) return false;

        return result.right?.value.toBigInt() === compareTo;
    }
}
