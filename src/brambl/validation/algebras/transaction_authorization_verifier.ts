import type { IoTransaction } from 'topl_common';
import type { TransactionAuthorizationError } from '../transaction_authorization_error.js';
import type DynamicContext from '@/quivr4s/quivr/runtime/dynamic_context.js';
import type ContextualValidation from '@/quivr4s/quivr/common/contextual_validation.js';


export default interface TransactionAuthorizationVerifier
  extends ContextualValidation<TransactionAuthorizationError, IoTransaction, DynamicContext<String>> {}
