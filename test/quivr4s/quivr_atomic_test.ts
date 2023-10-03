import { describe, it, expect } from "@jest/globals"
import { Proposer } from "../../src/quivr4s/classes/proposer"
import { Prover } from "../../src/quivr4s/classes/prover"
import { Data } from "../../src/quivr4s/common/types"
import { Verifier } from "../../src/quivr4s/classes/verifier"
import { MockHelpers } from "./helpers/mock_helpers"
import { ValidationErrorType, ValidationError } from "../../src/quivr4s/runtime/quivr_runtime_error"
import { either } from "fp-ts"


describe('Quivr Atomic Tests', () => {
    it('A locked proposition must return an LockedPropositionIsUnsatisfiable when evaluated', async () => {
        const lockedProposition = Proposer.lockedProposer(new Data());
        const lockedProverPoof = Prover.lockedProver();

        const result = await Verifier.verify(
            lockedProposition,
            lockedProverPoof,
            MockHelpers.dynamicContext(lockedProposition, lockedProverPoof),
        );
        expect(result._tag == "Left", true);


        const left = result as ValidationError;
        expect((left.type == ValidationErrorType.lockedPropositionIsUnsatisfiable), true);
    })
})