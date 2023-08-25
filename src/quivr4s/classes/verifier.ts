class Verifier {
    /// Will return [QuivrResult] Left => [QuivrRuntimeError.messageAuthorizationFailure] if the proof is invalid.
    static QuivrResult<bool> _evaluateBlake2b256Bind(
        String tag,
        Proof proof,
        TxBind proofTxBind,
        DynamicContext context,
    ) {
      final sb = context.signableBytes;
      final merge = utf8.encode(tag) + sb.value.toUint8List();
      final verifierTxBind = blake2b256.convert(merge).bytes;
  
      final result = ListEquality().equals(verifierTxBind, proofTxBind.value.toUint8List());

        return result ? QuivrResult.right(result) : QuivrResult.left(ValidationError.messageAuthorizationFailure());
    }

    static QuivrResult<bool> evaluateResult(
        QuivrResult<bool> messageResult,
            QuivrResult evalResult, {
                required Proposition proposition,
                required Proof proof,
            }) =>
(messageResult.isRight && messageResult.right == true && evalResult.isRight)
    ? QuivrResult.right(true)
    : quivrEvaluationAuthorizationFailure(proof, proposition);

    /// Verifies whether the given proof satisfies the given proposition
    /// Always returns Left [QuivrRuntimeError.lockedPropositionIsUnsatisfiable]
    static QuivrResult < bool > verifyLocked() {
    return QuivrResult.left(ValidationError.lockedPropositionIsUnsatisfiable());
}
  
    static QuivrResult < bool > verifyDigest(Proposition_Digest proposition, Proof_Digest proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..digest = proposition, Proof()..digest = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.digest, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final evalResult = context.digestVerify(
        proposition.routine, DigestVerification(digest: proposition.digest, preimage: proof.preimage));

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifySignature(
    Proposition_DigitalSignature proposition, Proof_DigitalSignature proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) =
        (Proposition()..digitalSignature = proposition, Proof()..digitalSignature = proof);
  
      final messageResult =
        _evaluateBlake2b256Bind(Tokens.digitalSignature, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final signedMessage = context.signableBytes;
      final verification = SignatureVerification(
        verificationKey: proposition.verificationKey,
        signature: proof.witness,
        message: Message(value: signedMessage.value.toList()));
  
      final evalResult = context.signatureVerify(proposition.routine, verification);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifyHeightRange(
    Proposition_HeightRange proposition, Proof_HeightRange proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..heightRange = proposition, Proof()..heightRange = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.heightRange, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final x = context.heightOf(proposition.chain);
      final QuivrResult < Int64 > chainHeight =
    x != null ? QuivrResult<Int64>.right(x) : quivrEvaluationAuthorizationFailure<Int64>(proof, proposition);

    if (chainHeight.isLeft) return QuivrResult<bool>.left(chainHeight.left);
  
      final height = chainHeight.right!;
  
      final evalResult = (proposition.max >= height) && (proposition.min <= height)
        ? QuivrResult<bool>.right(true)
        : quivrEvaluationAuthorizationFailure(proof, proposition);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifyTickRange(
    Proposition_TickRange proposition, Proof_TickRange proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..tickRange = proposition, Proof()..tickRange = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.tickRange, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;

    if (context.currentTick < proposition.min || context.currentTick > proposition.max) {
        return quivrEvaluationAuthorizationFailure(proof, proposition);
    }
      final tick = context.currentTick;
  
      final evalResult = ((proposition.min <= tick) && (tick <= proposition.max))
        ? QuivrResult<bool>.right(true)
        : quivrEvaluationAuthorizationFailure(proof, proposition);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifyExactMatch(
    Proposition_ExactMatch proposition, Proof_ExactMatch proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..exactMatch = proposition, Proof()..exactMatch = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.exactMatch, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final evalResult = context.exactMatch(proposition.location, proposition.compareTo);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifyLessThan(
    Proposition_LessThan proposition, Proof_LessThan proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..lessThan = proposition, Proof()..lessThan = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.lessThan, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final evalResult = context.lessThan(proposition.location, proposition.compareTo.value.toBigInt);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifyGreaterThan(
    Proposition_GreaterThan proposition, Proof_GreaterThan proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..greaterThan = proposition, Proof()..greaterThan = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.greaterThan, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final evalResult = context.greaterThan(proposition.location, proposition.compareTo.value.toBigInt);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static QuivrResult < bool > verifyEqualTo(Proposition_EqualTo proposition, Proof_EqualTo proof, DynamicContext context) {
    final(wrappedProposition, wrappedProof) = (Proposition()..equalTo = proposition, Proof()..equalTo = proof);
  
      final messageResult = _evaluateBlake2b256Bind(Tokens.equalTo, wrappedProof, proof.transactionBind, context);

    if (messageResult.isLeft) return messageResult;
  
      final evalResult = context.equalTo(proposition.location, proposition.compareTo.value.toBigInt);

    return evaluateResult(messageResult, evalResult, proposition: wrappedProposition, proof: wrappedProof);
}
  
    static Future < QuivrResult < bool >> verifyThreshold(
    Proposition_Threshold proposition, Proof_Threshold proof, DynamicContext context) async {
    final(wrappedProposition, wrappedProof) = (Proposition()..threshold = proposition, Proof()..threshold = proof);
    import { Either, left, right } from 'fp-ts/lib/Either';
    import { Blake2b256 } from '../hash/blake2b256';
    import { DynamicContext } from '../context/dynamic-context';
    import { Proof } from '../proof/proof';
    import { Proposition } from '../proposition/proposition';
    import { QuivrResult } from '../result/result';
    import { Tokens } from '../tokens/tokens';

    export class Verifier {
        private static async verifyLocked(): Promise<QuivrResult<boolean>> {
            return right(true);
        }

        private static async verifyDigest(
            propositionDigest: string,
            proofDigest: string,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofDigest);
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult = propositionDigest === proofDigest ? right(true) : left('Digests do not match');
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifySignature(
            propositionSignature: string,
            proofSignature: string,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofSignature);
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult = await context.verifySignature(proofSignature, propositionSignature);
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifyHeightRange(
            propositionHeightRange: [number, number],
            proofHeightRange: [number, number],
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofHeightRange.toString());
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult =
                proofHeightRange[0] >= propositionHeightRange[0] && proofHeightRange[1] <= propositionHeightRange[1]
                    ? right(true)
                    : left('Height range is invalid');
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifyTickRange(
            propositionTickRange: [number, number],
            proofTickRange: [number, number],
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofTickRange.toString());
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult =
                proofTickRange[0] >= propositionTickRange[0] && proofTickRange[1] <= propositionTickRange[1]
                    ? right(true)
                    : left('Tick range is invalid');
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifyLessThan(
            propositionLessThan: number,
            proofLessThan: number,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofLessThan.toString());
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult = proofLessThan < propositionLessThan ? right(true) : left('Value is not less than');
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifyGreaterThan(
            propositionGreaterThan: number,
            proofGreaterThan: number,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofGreaterThan.toString());
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult = proofGreaterThan > propositionGreaterThan ? right(true) : left('Value is not greater than');
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifyEqualTo(
            propositionEqualTo: number,
            proofEqualTo: number,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const messageResult = Blake2b256.hash(proofEqualTo.toString());
            if (messageResult.isLeft()) {
                return messageResult;
            }
            const evalResult = proofEqualTo === propositionEqualTo ? right(true) : left('Values are not equal');
            return Verifier.evaluateResult(messageResult, evalResult);
        }

        private static async verifyThreshold(
            propositionThreshold: number,
            proofThreshold: Proof[],
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const wrappedProposition = new Proposition();
            wrappedProposition.threshold = propositionThreshold;
            const wrappedProof = new Proof();
            wrappedProof.threshold = proofThreshold;

            const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.threshold, wrappedProof, proofThreshold, context);

            if (messageResult.isLeft()) {
                return messageResult;
            }

            // Initialize as true;
            let evalResult: QuivrResult<boolean> = right(false);

            if (propositionThreshold === 0) {
                evalResult = right(true);
            } else if (
                propositionThreshold > wrappedProposition.challenges.length ||
                proofThreshold.length === 0 ||
                proofThreshold.length !== wrappedProposition.challenges.length
            ) {
                evalResult = Verifier.quivrEvaluationAuthorizationFailure(wrappedProof, wrappedProposition);
            } else {
                let successCount = 0;
                for (let i = 0; i < wrappedProposition.challenges.length && successCount < propositionThreshold; i++) {
                    const challenge = wrappedProposition.challenges[i];
                    const response = proofThreshold[i];
                    const verifyResult = await Verifier.verify(challenge, response, context);
                    if (verifyResult.isRight()) {
                        successCount++;
                    }
                }
                if (successCount < propositionThreshold) {
                    evalResult = Verifier.quivrEvaluationAuthorizationFailure(wrappedProof, wrappedProposition);
                }
            }

            return Verifier.evaluateResult(messageResult, evalResult, wrappedProposition, wrappedProof);
        }

        private static async verifyNot(
            propositionNot: Proposition,
            proofNot: Proof,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const wrappedProposition = new Proposition();
            wrappedProposition.not = propositionNot;
            const wrappedProof = new Proof();
            wrappedProof.not = proofNot;

            const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.not, wrappedProof, proofNot.transactionBind, context);
            if (messageResult.isLeft()) {
                return messageResult;
            }

            const evalResult = await Verifier.verify(propositionNot.proposition, proofNot.proof, context);

            const beforeReturn = Verifier.evaluateResult(messageResult, evalResult, wrappedProposition, wrappedProof);

            return beforeReturn.isRight() ? Verifier.quivrEvaluationAuthorizationFailure(proofNot, propositionNot) : right(true);
        }

        private static async verifyAnd(
            propositionAnd: Proposition,
            proofAnd: Proof,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const wrappedProposition = new Proposition();
            wrappedProposition.and = propositionAnd;
            const wrappedProof = new Proof();
            wrappedProof.and = proofAnd;

            const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.and, wrappedProof, proofAnd.transactionBind, context);
            if (messageResult.isLeft()) {
                return messageResult;
            }

            const leftResult = await Verifier.verify(propositionAnd.left, proofAnd.left, context);
            if (leftResult.isLeft()) {
                return leftResult;
            }

            const rightResult = await Verifier.verify(propositionAnd.right, proofAnd.right, context);
            if (rightResult.isLeft()) {
                return rightResult;
            }

            // We're not checking the value of right as it's existence is enough to satisfy this condition
            if (leftResult.isRight() && rightResult.isRight()) {
                return right(true);
            }

            return Verifier.quivrEvaluationAuthorizationFailure(wrappedProposition, wrappedProof);
        }

        private static async verifyOr(
            propositionOr: Proposition,
            proofOr: Proof,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            const wrappedProposition = new Proposition();
            wrappedProposition.or = propositionOr;
            const wrappedProof = new Proof();
            wrappedProof.or = proofOr;

            const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.or, wrappedProof, proofOr.transactionBind, context);
            if (messageResult.isLeft()) {
                return messageResult;
            }

            const leftResult = await Verifier.verify(propositionOr.left, proofOr.left, context);
            if (leftResult.isRight()) {
                return right(true);
            }

            const rightResult = await Verifier.verify(propositionOr.right, proofOr.right, context);
            return rightResult;
        }

        static async verify(
            proposition: Proposition,
            proof: Proof,
            context: DynamicContext,
        ): Promise<QuivrResult<boolean>> {
            if (proposition.hasLocked() && proposition.hasLocked()) {
                return Verifier.verifyLocked();
            } else if (proposition.hasDigest() && proof.hasDigest()) {
                return Verifier.verifyDigest(proposition.digest, proof.digest, context);
            } else if (proposition.hasDigitalSignature() && proof.hasDigitalSignature()) {
                return Verifier.verifySignature(proposition.digitalSignature, proof.digitalSignature, context);
            } else if (proposition.hasHeightRange() && proof.hasHeightRange()) {
                return Verifier.verifyHeightRange(proposition.heightRange, proof.heightRange, context);
            } else if (proposition.hasTickRange() && proof.hasTickRange()) {
                return Verifier.verifyTickRange(proposition.tickRange, proof.tickRange, context);
            } else if (proposition.hasLessThan() && proof.hasLessThan()) {
                return Verifier.verifyLessThan(proposition.lessThan, proof.lessThan, context);
            } else if (proposition.hasGreaterThan() && proof.hasGreaterThan()) {
                return Verifier.verifyGreaterThan(proposition.greaterThan, proof.greaterThan, context);
            } else if (proposition.hasEqualTo() && proof.hasEqualTo()) {
                return Verifier.verifyEqualTo(proposition.equalTo, proof.equalTo, context);
            } else if (proposition.hasThreshold() && proof.hasThreshold()) {
                return Verifier.verifyThreshold(proposition.threshold, proof.threshold, context);
            } else if (proposition.hasNot() && proof.hasNot()) {
                return Verifier.verifyNot(proposition.not, proof.not, context);
            } else if (proposition.hasAnd() && proof.hasAnd()) {
                return Verifier.verifyAnd(proposition.and, proof.and, context);
            } else if (proposition.hasOr() && proof.hasOr()) {
                return Verifier.verifyOr(proposition.or, proof.or, context);
            } else {
                return Verifier.quivrEvaluationAuthorizationFailure(proof, proposition);
            }
        }

        private static async _evaluateBlake2b256Bind(
            token: Tokens,
            proof: Proof,
            transactionBind: string,
            context: DynamicContext,
        ): Promise<Either<string, string>> {
            const message = `${token.toString()}${transactionBind}${proof.toString()}`;
            return Blake2b256.hash(message);
        }

        private static evaluateResult(
            messageResult: Either<string, string>,
            evalResult: QuivrResult<boolean>,
            proposition?: Proposition,
            proof?: Proof,
        ): QuivrResult<boolean> {
            if (evalResult.isLeft()) {
                return evalResult;
            }
            const message = messageResult.getOrElse('Message hash failed');
            return right(evalResult.getOrElse(false)).mapLeft((error) =>
                Verifier.quivrEvaluationAuthorizationFailure(proof, proposition, error, message),
            );
        }

        private static quivrEvaluationAuthorizationFailure(
            proof: Proof,
            proposition: Proposition,
            error?: string,
            message?: string,
        ): QuivrResult<boolean> {
            const wrappedProposition = proposition ? new Proposition(proposition) : undefined;
            const wrappedProof = proof ? new Proof(proof) : undefined;
            const errorMessage = error || 'Authorization failure';
            const messageHash = message || '';
            return left(`${errorMessage} - ${messageHash}`).mapLeft((error) =>
                Verifier.quivrEvaluationAuthorizationFailure(wrappedProof, wrappedProposition, error, messageHash),
            );
        }
    }
