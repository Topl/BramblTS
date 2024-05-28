// A Verification Context opinionated to the Topl context.

import { none, optionOps, some, type Option } from '@/common/functional/either.js';
import type DigestVerifier from '@/quivr4s/algebras/digest_verifer.js';
import type SignatureVerifier from '@/quivr4s/algebras/signature_verifier.js';
import type ParsableDataInterface from '@/quivr4s/quivr/common/parsable_data_interface.js';
import DynamicContext from '@/quivr4s/quivr/runtime/dynamic_context.js';
import { SignableBytes, type Datum, type IoTransaction } from 'topl_common';
import Blake2b256DigestInterpreter from './validation/blake2b256_digest_interpreter.js';
import ExtendedEd25519SignatureInterpreter from './validation/extended_ed25519_signature_interpreter.js';
import Sha256DigestInterpreter from './validation/sha256_digest_interpreter.js';

// TODO  fix inheritance from base dynamiccontext
// signableBytes, currentTick and the datums are dynamic
export class Context extends DynamicContext<string> {
  readonly tx: IoTransaction;
  readonly curTick: BigInt;
  readonly heightDatums: (label: string) => Option<Datum>;

  constructor (tx: IoTransaction, curTick: number, heightDatums: (label: string) => Option<Datum>) {
    // Setup "overrides"
    const hashingRoutines: Map<string, DigestVerifier> = new Map<string, DigestVerifier>([
      ['Blake2b256', new Blake2b256DigestInterpreter()],
      ['Sha256', new Sha256DigestInterpreter()]
    ]);

    const signingRoutines: Map<string, SignatureVerifier> = new Map<string, SignatureVerifier>([
      ['ExtendedEd25519', new ExtendedEd25519SignatureInterpreter()]
    ]);

    const interfaces: Map<string, ParsableDataInterface> = new Map<string, ParsableDataInterface>();

    const signableBytes: SignableBytes = tx.signable();

    const currentTick: bigint = BigInt(curTick);

    const datums: (k: String) => Option<Datum> = heightDatums;

    const heightOf: (label: string) => Option<bigint> = (label: string) => {
      return optionOps.flatMap(heightDatums(label), datum => {
        switch (datum.value.case) {
          case 'header':
            return some(datum.value.value.event.height);
          default:
            return none;
        }
      });
    };

    /// call super with "overrides"
    super(datums, interfaces, signingRoutines, hashingRoutines, signableBytes, currentTick, heightOf);

    /// Store for future use
    this.tx = tx;
    this.curTick = BigInt(curTick);
    this.heightDatums = heightDatums;
  }
}
