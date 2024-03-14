import { Either, left, right, flatMap } from 'fp-ts/Either';
import { PropositionTemplate, ThresholdTemplate } from './proposition_template.js';
import { BuilderError } from '../builder_error.js';
import { VerificationKey, Proposition_Threshold } from 'topl_common';
import { Lock, Challenge } from 'topl_common';

export abstract class LockTemplate {
  lockType: LockType;
  abstract build(entityVks: VerificationKey[]): Either<BuilderError, Lock>;
}

class LockType {
  public label: string;
  constructor(label: string) {
    this.label = label;
  }
}

class LockTypes {
  public static predicate = new LockType('predicate');
}

export class PredicateTemplate implements LockTemplate {
  public innerTemplates: PropositionTemplate[];
  public threshold: number;
  public lockType = LockTypes.predicate;

  constructor(innerTemplates: PropositionTemplate[], threshold: number) {
    this.innerTemplates = innerTemplates;
    this.threshold = threshold;
  }

  build(entityVks: VerificationKey[]): Either<BuilderError, Lock> {
    const result = new ThresholdTemplate(this.innerTemplates, this.threshold).build(entityVks);

    const getLock = function (ip) {
      if (ip instanceof Proposition_Threshold) {
        const innerPropositions = ip.challenges;

        return right(
          new Lock(
            {
            predicate: new Lock.Predicate({
              challenges: innerPropositions.map((prop) => new Challenge({ revealed: prop })),
              threshold: this.threshold,
            }),
          }
          ),
        ) as Either<BuilderError, Lock>;
      } else {
        return left(new BuilderError(`Unexpected inner proposition type: ${typeof result}`));
      }
    };

    return flatMap(getLock)(result);
  }

  //used for pickling
  toJson() {
    return {
      type: this.lockType.label,
      threshold: this.threshold,
      innerTemplates: this.innerTemplates.map((innerTemplate) => {
        return innerTemplate.toJson();
      })
    };
  }

  fromJson(json): PredicateTemplate {
    const innerTemplates = json.innerTemplates.map((innerTemplateJson) => {
      return PropositionTemplate.fromJson(innerTemplateJson);
    });

    return new PredicateTemplate(innerTemplates, json.threshold);
  }
}
