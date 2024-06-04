import { isLeft, left, right, type Either, type Option } from '@/common/functional/brambl_fp.js';
import { Data, Datum, DigestVerification, SignableBytes, SignatureVerification } from 'topl_common';

import type DigestVerifier from '@/quivr4s/algebras/digest_verifer.js';
import type SignatureVerifier from '@/quivr4s/algebras/signature_verifier.js';
import type ParsableDataInterface from '../common/parsable_data_interface.js';
import type { QuivrResult } from '../common/quivr_result.js';
import { ValidationError, type QuivrRuntimeError } from './quivr_runtime_error.js';

export default class DynamicContext<K> {
  datums: (k: K) => Option<Datum>;
  interfaces: Map<K, ParsableDataInterface>;
  signingRoutines: Map<K, SignatureVerifier>;
  hashingRoutines: Map<K, DigestVerifier>;
  signableBytes: SignableBytes;
  currentTick: bigint;
  heightOf?: (label: string) => Option<bigint>;

  constructor (
    datums: (k: K) => Option<Datum>,
    interfaces: Map<K, ParsableDataInterface>,
    signingRoutines: Map<K, SignatureVerifier>,
    hashingRoutines: Map<K, DigestVerifier>,
    signableBytes: SignableBytes,
    currentTick: bigint,
    heightOf?: (label: string) => Option<bigint>
  ) {
    this.datums = datums;
    this.interfaces = interfaces;
    this.signingRoutines = signingRoutines;
    this.hashingRoutines = hashingRoutines;
    this.signableBytes = signableBytes;
    this.currentTick = currentTick;
    this.heightOf = heightOf;
  }

  digestVerify (routine: K, verification: DigestVerification): QuivrResult<DigestVerification> {
    const verifier = this.hashingRoutines.has(routine) ? this.hashingRoutines.get(routine) : null;

    if (verifier === null)
      return left(
        ValidationError.failedToFindDigestVerifier({
          name: 'DynamicContext',
          message: `failed to find digest verifier for ${routine}`
        })
      );

    const result = verifier.validate(verification) as QuivrResult<DigestVerification>;
    if (isLeft(result)) return result;

    return right(result.right);
  }

  signatureVerify (routine: K, verification: SignatureVerification): QuivrResult<SignatureVerification> {
    const verifier = this.signingRoutines.has(routine) ? this.signingRoutines.get(routine) : null;

    if (verifier === null)
      return left(
        ValidationError.failedToFindSignatureVerifier({
          name: 'DynamicContext',
          message: `failed to find signature verifier for ${routine}`
        })
      );

    const result = verifier.validate(verification);
    if (isLeft(result)) return result;

    return right(result.right);
  }

  useInterface (label: K): Either<QuivrRuntimeError, Data> {
    const interfaceObj = this.interfaces.has(label) ? this.interfaces.get(label) : null;

    if (interfaceObj === null)
      return left(
        ValidationError.failedToFindInterface({
          name: 'DynamicContext',
          message: `failed to find interface for ${label}`
        })
      );

    const f = (data: Data): QuivrResult<Data> => {
      return right(data);
    };

    return interfaceObj.parse<QuivrRuntimeError, Data>(f);
  }

  exactMatch (label: K, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (isLeft(result)) return false;

    return JSON.stringify(result.right?.value) === JSON.stringify(compareTo);
  }

  lessThan (label: K, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (isLeft(result)) return false;

    return result.right.value <= compareTo;
  }

  greaterThan (label: K, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (isLeft(result)) return false;

    return result.right.value >= compareTo;
  }

  equalTo (label: K, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (isLeft(result)) return false;

    return result.right.value === compareTo;
  }
}
