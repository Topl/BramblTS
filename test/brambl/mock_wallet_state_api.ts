import type { LockTemplate } from '@/brambl/builders/locks/lock_template.js';
import { WalletStateAlgebra } from '@/brambl/data_api/data_api.js';
import type {
  Evidence,
  Indices,
  KeyPair,
  Lock_Predicate,
  Preimage,
  Proposition_Digest,
  Proposition_DigitalSignature,
} from 'topl_common';
import { mockDigestProposition, mockIndices, mockPreimage, mockSignatureProposition } from './mock_helpers.js';

/**
 * Mock Implementation of the WalletStateAlgebra for testing
 */
export class MockWalletStateApi extends WalletStateAlgebra {
  readonly propEvidenceToIdx: Map<Evidence, Indices> = new Map([
    [mockSignatureProposition.value.value.bSizedEvidence(), mockIndices],
  ]);

  readonly propEvidenceToPreimage: Map<Evidence, Preimage> = new Map([
    [mockDigestProposition.value.value.bSizedEvidence(), mockPreimage],
    [mockDigestProposition.value.value.bSizedEvidence(), mockPreimage],
  ]);

  override getIndicesBySignature(signatureProposition: Proposition_DigitalSignature): Promise<Indices> {
    return Promise.resolve(this.propEvidenceToIdx.get(signatureProposition.bSizedEvidence()));
  }
  override getPreimage(digestProposition: Proposition_Digest): Promise<Preimage> {
    return Promise.resolve(this.propEvidenceToPreimage.get(digestProposition.bSizedEvidence()));
  }

  override addPreimage(preimage: Preimage, digest: Proposition_Digest): Promise<void> {
    this.propEvidenceToPreimage.set(digest.bSizedEvidence(), preimage);
    return Promise.resolve();
  }

  /// The following are not implemented since they are not used in the tests

  override getCurrentAddress(): Promise<string> {
    throw new Error('Method not implemented.');
  }

  override getInteractionList(_fellowship: string, _template: string): Promise<[Indices, string][]> {
    throw new Error('Method not implemented.');
  }
  override setCurrentIndices(_fellowship: string, _template: string, _interaction: number): Promise<Indices> {
    throw new Error('Method not implemented.');
  }

  override initWalletState(_networkId: number, _ledgerId: number, _mainKey: KeyPair): Promise<void> {
    throw new Error('Method not implemented.');
  }

  override updateWalletState(
    _lockPredicate: string,
    _lockAddress: string,
    _routine: string | null,
    _vk: string | null,
    _indices: Indices,
  ): Promise<void> {
    throw new Error('Method not implemented.');
  }
  override getCurrentIndicesForFunds(
    _fellowship: string,
    _template: string,
    _someInteraction: number | null,
  ): Promise<Indices> {
    throw new Error('Method not implemented.');
  }
  override validateCurrentIndicesForFunds(
    _fellowship: string,
    _template: string,
    _someInteraction: number | null,
  ): Promise<Indices> {
    throw new Error('Method not implemented.');
  }
  override getNextIndicesForFunds(_fellowship: string, _template: string): Promise<Indices> {
    throw new Error('Method not implemented.');
  }
  override getLockByIndex(_indices: Indices): Promise<Lock_Predicate> {
    throw new Error('Method not implemented.');
  }
  override getLockByAddress(_lockAddress: string): Promise<Lock_Predicate> {
    throw new Error('Method not implemented.');
  }
  override getAddress(_fellowship: string, _template: string, _someInteraction: number | null): Promise<string> {
    throw new Error('Method not implemented.');
  }
  override addEntityVks(_fellowship: string, _template: string, _fellows: string[]): Promise<void> {
    throw new Error('Method not implemented.');
  }
  override getEntityVks(_fellowship: string, _template: string): Promise<string[]> {
    throw new Error('Method not implemented.');
  }
  override addNewLockTemplate(_template: string, _lockTemplate: LockTemplate): Promise<void> {
    throw new Error('Method not implemented.');
  }
  override getLockTemplate(_template: string): Promise<LockTemplate> {
    throw new Error('Method not implemented.');
  }
  override getLock(_fellowship: string, _template: string, _nextInteraction: number): Promise<Lock> {
    throw new Error('Method not implemented.');
  }
}
