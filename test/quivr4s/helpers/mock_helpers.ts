import { either } from "fp-ts";
import { ValidationError } from "../../../src/quivr4s/runtime/quivr_runtime_error";
import { VerySecureSignatureRoutine } from "./very_secure_signature_routine";
import { DynamicContext } from "../../../src/quivr4s/runtime/dynamic_context";
import { Datum, Event, SignableBytes } from "../../../src/quivr4s/common/types";

export class MockHelpers {
    static heightString = "height";
    static signatureString = "verySecure";
    static hashString = "blake2b256";
    static saltString = "I am a digest";
    static preimageString = "I am a preimage";

    static signableBytes: SignableBytes = new SignableBytes({ value: Uint8Array.from("someSignableBytes".split("").map((c) => c.charCodeAt(0))) });

    static dynamicContext(proposition, proof): DynamicContext {
        const mapOfDatums: Map<string, Datum | null> = new Map();
        mapOfDatums.set(this.heightString, new Datum({
            header: new Datum.Header({ event: new Event.Header({ height: 999 }) })
        }));

        const mapOfInterfaces = new Map();

        const mapOfSigningRoutines = new Map();
        mapOfSigningRoutines.set(this.signatureString, (v) => {
            if (
                VerySecureSignatureRoutine.verify(
                    new Uint8Array(v.signature.value),
                    new Uint8Array(v.message.value),
                    new Uint8Array(v.verificationKey.ed25519.value)
                )
            ) {
                return either.right(v);
            } else {
                return either.left(
                    ValidationError.messageAuthorizationFailure({
                        name: proof.toString(),
                        message: "Failed to verify signature",
                    })
                );
            }
        },);




        const mapOfHashingRoutines = new Map();
        mapOfHashingRoutines.set(this.hashString,
            (v) => {
                const test = Blake2b256.hash(
                    new Uint8Array([...v.preimage.input, ...v.preimage.salt])
                );
                if (new Uint8Array(v.digest.value).toString() === test.toString()) {
                    return either.right(v);
                } else {
                    return either.left(
                        ValidationError.lockedPropositionIsUnsatisfiable({
                            name: v.toString(),
                            message: "Failed to verify digest",
                        })
                    );
                }
            },
        );



        const currentTick = 999;

        const heightOf = (label) => {
            const datum = mapOfDatums[label];
            if (datum != null) {
                const header = datum.header;
                const eventHeader = header.event;
                return eventHeader.height;
            }
            return null;
        };

        return new DynamicContext(
            mapOfDatums,
            mapOfInterfaces,
            mapOfSigningRoutines,
            mapOfHashingRoutines,
            MockHelpers.signableBytes,
            currentTick,
            heightOf,
        );
    }
}
