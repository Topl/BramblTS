import type { NonEmptyArray } from '@/common/functional/brambl_fp.js';
import type { IoTransaction } from 'topl_common';
import type { TransactionSyntaxError } from '../transaction_syntax_error.js';
import type ContextlessValidation from '@/quivr4s/quivr/common/contextless_validation.js';

export default interface TransactionSyntaxVerifier
  extends ContextlessValidation<NonEmptyArray<TransactionSyntaxError>, IoTransaction> {}
