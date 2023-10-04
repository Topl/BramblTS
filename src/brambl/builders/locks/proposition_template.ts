import { Either, left, right, isLeft, isRight } from 'fp-ts/Either';
import { BuilderError } from '../builder_error.js';
import { Data, Digest, Proposition, VerificationKey } from "../../../quivr4s/common/types.js";
import { Proposer } from '../../../quivr4s/classes/proposer.js';

enum PropositionType {
    locked = 'locked',
    height = 'height',
    tick = 'tick',
    digest = 'digest',
    signature = 'signature',
    and = 'and',
    or = 'or',
    not = 'not',
    threshold = 'threshold',
}

export class UnableToBuildPropositionTemplate extends BuilderError {
    constructor({message}: {message: string}) {
        super(message);
    }
}

export abstract class PropositionTemplate {
    public propositionType: PropositionType;
    abstract build(entityVks: VerificationKey[]): Either<BuilderError, Proposition>;
}

export class LockedTemplate implements PropositionTemplate {
    public data?: Data;
    public propositionType = PropositionType.locked;

    constructor(data: Data) {
        this.data = data;
    }

    //TODO: unused var
    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            return right(Proposer.lockedProposer(this.data));
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
};

export class HeightTemplate implements PropositionTemplate {
    public chain: string;
    public min: number;
    public max: number;
    public propositionType = PropositionType.height;

    constructor(chain: string, min: number, max: number) {
        this.chain = chain;
        this.min = min;
        this.max = max;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            return right(Proposer.heightProposer(this.chain, this.min, this.max));
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class TickTemplate implements PropositionTemplate {
    public min: number;
    public max: number;
    public propositionType = PropositionType.tick;

    constructor(min: number, max: number) {
        this.min = min;
        this.max = max;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            return right(Proposer.tickProposer(this.min, this.max));
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class DigestTemplate implements PropositionTemplate {
    public routine: string;
    public digest: Digest;
    public propositionType = PropositionType.digest;

    constructor(routine: string, digest: Digest) {
        this.routine = routine;
        this.digest = digest;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            return right(Proposer.digestProposer(this.routine, this.digest));
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class SignatureTemplate implements PropositionTemplate {
    public routine: string;
    public entityIdx: number;
    public propositionType = PropositionType.signature;

    constructor(routine: string, entityIdx: number) {
        this.routine = routine;
        this.entityIdx = entityIdx;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            if (this.entityIdx >= 0 && this.entityIdx < entityVks.length) {
                return right(Proposer.signatureProposer(this.routine, entityVks[this.entityIdx]));
            } else {
                return left(new BuilderError(`Signature Proposition failed. Index: ${this.entityIdx}. Length of VKs: ${entityVks.length}`));
            }
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class AndTemplate implements PropositionTemplate {
    public leftTemplate: PropositionTemplate;
    public rightTemplate: PropositionTemplate;
    public propositionType = PropositionType.and;

    constructor(leftTemplate: PropositionTemplate, rightTemplate: PropositionTemplate) {
        this.leftTemplate = leftTemplate;
        this.rightTemplate = rightTemplate;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            const lp = this.leftTemplate.build(entityVks);
            const rp = this.rightTemplate.build(entityVks);
            if (isRight(lp) && isRight(rp)) {
                return right(Proposer.andProposer(lp.right, rp.right));
            } else if (isLeft(lp)) {
                return lp;
            } else {
                return rp;
            }
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class OrTemplate implements PropositionTemplate {
    public leftTemplate: PropositionTemplate;
    public rightTemplate: PropositionTemplate;
    public propositionType = PropositionType.or;

    constructor(leftTemplate: PropositionTemplate, rightTemplate: PropositionTemplate) {
        this.leftTemplate = leftTemplate;
        this.rightTemplate = rightTemplate;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            const lp = this.leftTemplate.build(entityVks);
            const rp = this.rightTemplate.build(entityVks);
            if (isRight(lp) && isRight(rp)) {
                return right(Proposer.orProposer(lp.right, rp.right));
            } else if (isLeft(lp)) {
                return lp;
            } else {
                return rp;
            }
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class NotTemplate implements PropositionTemplate {
    public innerTemplate: PropositionTemplate;
    public propositionType = PropositionType.not;

    constructor(innerTemplate: PropositionTemplate) {
        this.innerTemplate = innerTemplate;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {
        try {
            const ip = this.innerTemplate.build(entityVks);
            if (isRight(ip)) {
                return right(Proposer.notProposer(ip.right));
            } else {
                return ip;
            }    
        } catch (e) {
            return left(new BuilderError(e.toString()));
        }
    }
}

export class ThresholdTemplate implements PropositionTemplate {
    public innerTemplates: PropositionTemplate[];
    public threshold: number;
    public propositionType = PropositionType.threshold;

    constructor(innerTemplates: PropositionTemplate[], threshold: number) {
        this.innerTemplates = innerTemplates;
        this.threshold = threshold;
    }

    build(entityVks: VerificationKey[]): Either<BuilderError, Proposition> {

        const buildInner = (
            templates: PropositionTemplate[],
            accumulator: Either<BuilderError, Proposition[]>
        ): Either<BuilderError, Proposition[]> => {
    
            if (isLeft(accumulator)) {
                return accumulator;
            } 
    
            if (templates.length === 0) {
                return accumulator;
            }
    
            const accProps = accumulator.right;
            const head = templates[0].build(entityVks);
    
            if (isLeft(head)) {
                return head;
            }
    
            const updatedProps = [...accProps, head.right];
            return buildInner(templates.slice(1), right(updatedProps));
        }
    
        const result = buildInner(this.innerTemplates, right([]));
    
        if (isLeft(result)) {
            return result;
        }
    
        try {
            return right(Proposer.thresholdProposer(result.right, this.threshold));
        } catch (e) {
            return left(new BuilderError(e.toString(), e));
        }
    }

}