import { VerificationKey,
    Proposition_DigitalSignature,
    Proposition_Digest,
    Preimage,
 } from "../../quivr4s/common/types.js";

import {Indices, Lock_Predicate} from "../common/types.js"

import { LockTemplate } from "../builders/locks/lock_template.js";


export abstract class WalletStateAlgebra {
    abstract initWalletState(networkId: number, ledgerId: number, vk: VerificationKey): Promise<void>;

    abstract getIndicesBySignature(signatureProposition: Proposition_DigitalSignature): Promise<Indices | null>;

    abstract getPreimage(digestProposition: Proposition_Digest): Promise<Preimage | null>;

    abstract getCurrentAddress(): Promise<string>;

    abstract updateWalletState(
        lockPredicate: string, 
        lockAddress: string, 
        routine: string | null, 
        vk: string | null, 
        indices: Indices
    ): Promise<void>;

    abstract getCurrentIndicesForFunds(party: string, contract: string, someState?: number): Promise<Indices | null>;

    abstract validateCurrentIndicesForFunds(party: string, contract: string, someState?: number): Promise<[string, Indices] | null>;

    abstract getNextIndicesForFunds(party: string, contract: string): Promise<Indices | null>;

    abstract getLockByIndex(indices: Indices): Promise<Lock_Predicate | null>;

    abstract getAddress(party: string, contract: string, someState?: number): Promise<string | null>;

    abstract addEntityVks(party: string, contract: string, entities: string[]): Promise<void>;

    abstract getEntityVks(party: string, contract: string): Promise<string[] | null>;

    abstract addNewLockTemplate(contract: string, lockTemplate: LockTemplate): Promise<void>;

    abstract getLockTemplate(contract: string): Promise<LockTemplate | null>;

    abstract getLock(party: string, contract: string, nextState: number): Promise<Lock | null>;
}