// A Verification Context opinionated to the Topl context.


import { SignableBytes, type Datum, type IoTransaction } from 'topl_common';
import Blake2b256DigestInterpreter from './validation/blake2b256_digest_interpreter.js';
import { type Option, none, some } from '@/common/functional/either.js';
import type SignatureVerifier from '@/quivr4s/algebras/signature_verifier.js';
import type DigestVerifier from '@/quivr4s/algebras/digest_verifer.js';
import Sha256DigestInterpreter from './validation/sha256_digest_interpreter.js';
import ExtendedEd25519SignatureInterpreter from './validation/extended_ed25519_signature_interpreter.js';
import type ParsableDataInterface from '@/quivr4s/quivr/common/parsable_data_interface.js';

// signableBytes, currentTick and the datums are dynamic
export default class Context {
  tx: IoTransaction;
  curTick: number;
  heightDatums: (label: string) => Datum | undefined;
  hashingRoutines: Record<string, DigestVerifier>;
  signingRoutines: Record<string, SignatureVerifier>;
  interfaces: Record<string, ParsableDataInterface>;

  constructor (tx: IoTransaction, curTick: number, heightDatums: (label: string) => Datum | undefined) {
    this.tx = tx;
    this.curTick = curTick;
    this.heightDatums = heightDatums;

    this.hashingRoutines = {
      Blake2b256: new Blake2b256DigestInterpreter(),
      Sha256: new Sha256DigestInterpreter()
    };

    this.signingRoutines = {
      ExtendedEd25519: new ExtendedEd25519SignatureInterpreter()
    };

    this.interfaces = {}; // Arbitrary
  }

  signableBytes (): SignableBytes {
    return this.tx.signable();
  }

  currentTick (): number {
    return this.curTick;
  }

  heightOf (label: string): Option<bigint> {
    const datum = this.heightDatums(label);
    if (datum.value.case === 'header') {
      return some(datum.value.value.event.height);
    }
    return none;
  }
}
