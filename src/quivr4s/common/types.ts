import * as proof from '../../../proto/quivr/models/proof.js';
import * as shared from '../../../proto/quivr/models/shared.js';
import * as proposition from '../../../proto/quivr/models/proposition.js';


/// Proofs
export class Proof extends proof.quivr.models.Proof { };
export class Proof_Digest extends proof.quivr.models.Proof.Digest { }
export class Proof_DigitalSignature extends proof.quivr.models.Proof.DigitalSignature { };
export class Proof_HeightRange extends proof.quivr.models.Proof.HeightRange { };

/// Shared
export class TxBind extends shared.quivr.models.TxBind { };
export class SignableBytes extends shared.quivr.models.SignableBytes { };
export class Preimage extends shared.quivr.models.Preimage { };
export class Witness extends shared.quivr.models.Witness { };
export class Digest extends shared.quivr.models.Digest { };
export class VerificationKey extends shared.quivr.models.VerificationKey { };
export class Data extends shared.quivr.models.Data { };
export class DigestVerification extends shared.quivr.models.DigestVerification { };
export class SignatureVerification extends shared.quivr.models.SignatureVerification { };
export class Message extends shared.quivr.models.Message { };



/// Propositions
export class Proposition extends proposition.quivr.models.Proposition { };
export class Proposition_Digest extends proposition.quivr.models.Proposition.Digest { }
export class Proposition_DigitalSignature extends proposition.quivr.models.Proposition.DigitalSignature { };
export class Proposition_HeightRange extends proposition.quivr.models.Proposition.HeightRange { };
export class TickRange extends proposition.quivr.models.Proposition.TickRange { };
export class ExactMatch extends proposition.quivr.models.Proposition.ExactMatch { };
export class LessThan extends proposition.quivr.models.Proposition.LessThan { };
export class GreaterThan extends proposition.quivr.models.Proposition.GreaterThan { };
export class EqualTo extends proposition.quivr.models.Proposition.EqualTo { };
export class Threshold extends proposition.quivr.models.Proposition.Threshold { };
export class Not extends proposition.quivr.models.Proposition.Not { };
export class And extends proposition.quivr.models.Proposition.And { };
