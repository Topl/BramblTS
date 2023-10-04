import { either } from 'fp-ts';
import * as datum from '../../../proto/brambl/models/datum.js';
import { DigestVerifier } from '../algebras/digest_verifer.js';
import { SignatureVerifier } from '../algebras/signature_verifier.js';
import { ParsableDataInterface } from '../common/parsable_data_interface.js';
import { QuivrResult } from '../common/quivr_result.js';
import { Data, DigestVerification, SignableBytes, SignatureVerification } from '../common/types.js';
import { ValidationError } from './quivr_runtime_error.js';

export class DynamicContext {
  datum: Map<string, datum.co.topl.brambl.models.Datum | null>;
  interfaces: Map<string, ParsableDataInterface>;
  signingRoutines: Map<string, SignatureVerifier<unknown>>;
  hashingRoutines: Map<string, DigestVerifier<unknown>>;
  signableBytes: SignableBytes;
  currentTick: number;
  heightOf?: (arg0: string) => number | null;

  constructor(
    datum: Map<string, datum.co.topl.brambl.models.Datum | null>,
    interfaces: Map<string, ParsableDataInterface>,
    signingRoutines: Map<string, SignatureVerifier<unknown>>,
    hashingRoutines: Map<string, DigestVerifier<unknown>>,
    signableBytes: SignableBytes,
    currentTick: number,
    heightOf?: (arg0: string) => number | null,
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

    if (verifier === null)
      return either.left(
        ValidationError.failedToFindDigestVerifier({
          name: 'DynamicContext',
          message: `failed to find digest verifier for ${routine}`,
        }),
      );

    const result = verifier.validate(verification) as QuivrResult<DigestVerification>;
    if (result._tag === 'Left') return result;

    return either.right(result.right);
  }

  signatureVerify(routine: string, verification: SignatureVerification): QuivrResult<SignatureVerification> {
    const verifier = this.signingRoutines.has(routine) ? this.signingRoutines.get(routine) : null;

    if (verifier === null)
      return either.left(
        ValidationError.failedToFindSignatureVerifier({
          name: 'DynamicContext',
          message: `failed to find signature verifier for ${routine}`,
        }),
      );

    const result = verifier.validate(verification) as QuivrResult<SignatureVerification>;
    if (result._tag === 'Left') return result;

    return either.right(result.right);
  }

  useInterface(label: string): QuivrResult<Data> {
    const interfaceObj = this.interfaces.has(label) ? this.interfaces.get(label) : null;

    if (interfaceObj === null)
      return either.left(
        ValidationError.failedToFindInterface({
          name: 'DynamicContext',
          message: `failed to find interface for ${label}`,
        }),
      );

    return either.right(interfaceObj.parse((data: Data) => data));
  }

  exactMatch(label: string, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (result._tag === 'Left') return false;

    return JSON.stringify(result.right?.value) === JSON.stringify(compareTo);
  }

  lessThan(label: string, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (result._tag === 'Left') return false;

    return result.right!.value <= compareTo;
  }

  greaterThan(label: string, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (result._tag === 'Left') return false;

    return result.right!.value >= compareTo;
  }

  equalTo(label: string, compareTo: Uint8Array): boolean {
    const result = this.useInterface(label);

    if (result._tag === 'Left') return false;

    return result.right?.value === compareTo;
  }
}
