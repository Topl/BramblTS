import type { SignatureVerification } from 'topl_common';
import type ContextlessValidation from '../quivr/common/contextless_validation.js';
import type { QuivrRuntimeError } from '../quivr/runtime/quivr_runtime_error.js';

export default interface SignatureVerifier extends ContextlessValidation<QuivrRuntimeError, SignatureVerification> {}
