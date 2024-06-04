import { left, none, right, some, type Either, type Option } from '@/common/functional/brambl_fp.js';
import { blake2b512 } from '@/crypto/crypto.js';
import DigestVerifier from '@/quivr4s/algebras/digest_verifer.js';
import SignatureVerifier from '@/quivr4s/algebras/signature_verifier.js';
import { ValidationError } from '@/quivr4s/quivr.js';
import type ParsableDataInterface from '@/quivr4s/quivr/common/parsable_data_interface.js';
import DynamicContext from '@/quivr4s/quivr/runtime/dynamic_context.js';
import type { QuivrRuntimeError } from '@/quivr4s/quivr/runtime/quivr_runtime_error.js';
import {
    Datum,
    Datum_Header,
    DigestVerification,
    Event_Header,
    Proof,
    Proposition,
    SignableBytes,
    SignatureVerification
} from 'topl_common';
import { VerySecureSignatureRoutine } from './very_secure_signature_routine.js';

export class MockHelpers {
  static heightString = 'height';
  static signatureString = 'verySecure';
  static hashString = 'blake2b256';
  static saltString = 'I am a digest';
  static preimageString = 'I am a preimage';

  static signableBytes = new SignableBytes({ value: Buffer.from('someSignableBytes', 'utf8') });

  static dynamicContext (proposition: Proposition, proof: Proof) {
    const header = new Datum().withHeader(
      new Datum_Header({
        event: new Event_Header({ height: BigInt(999) })
      })
    );

    const mapOfDatums: Map<string, Datum> = new Map([['height', header]]);

    const mapOfInterfaces: Map<string, ParsableDataInterface> = new Map();

    const signatureVerifier = (t: SignatureVerification): Either<QuivrRuntimeError, SignatureVerification> => {
      switch (t.verificationKey.vk.case) {
        case 'ed25519':
          if (VerySecureSignatureRoutine.verify(t.signature.value, t.message.value, t.verificationKey.vk.value.value)) {
            return right(t);
          } else {
            return left(
              ValidationError.messageAuthorizationFailure({
                name: 'VerySecureSignatureRoutine',
                message: `Verification failed ${proof}`
              })
            );
          }
        default:
          return left(ValidationError.userProvidedInterfaceFailure({ name: '', message: `Verification failed` }));
      }
    };

    const mapOfSigningRoutines: Map<string, SignatureVerifier> = new Map([
      [MockHelpers.signatureString, new SignatureVerifier(signatureVerifier)]
    ]);

    const digestVerifier = (t: DigestVerification): Either<QuivrRuntimeError, DigestVerification> => {
      const test = blake2b512.hash(Buffer.from([...t.preimage.input, ...t.preimage.salt]));
      if (t.digest.value.bEquals(test)) {
        return right(t);
      } else {
        return left(ValidationError.lockedPropositionIsUnsatisfiable({ name: `${t}`, message: `Verification failed` }));
      }
    };

    const mapOfHashingRoutine: Map<string, DigestVerifier> = new Map([
      [MockHelpers.hashString, new DigestVerifier(digestVerifier)]
    ]);

    const currentTick = BigInt(999);

    const heightOf = (label: string) => {
      const datum = mapOfDatums[label];
      if (datum && datum.header && datum.header.event && datum.header.event.height) {
        return datum.header.event.height;
      } else {
        return null;
      }
    };

    const datumable = (k: string): Option<Datum> => {
      const datum = mapOfDatums[k];
      if (datum) {
        return some<Datum>(datum);
      } else {
        return none;
      }
    };

    return new DynamicContext<string>(
      datumable,
      mapOfInterfaces,
      mapOfSigningRoutines,
      mapOfHashingRoutine,
      MockHelpers.signableBytes,
      currentTick,
      heightOf
    );
  }
}
