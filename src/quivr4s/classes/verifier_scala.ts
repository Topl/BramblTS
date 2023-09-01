import * as E from 'fp-ts/Either';

const collectResult = (proposition, proof) => (msgResult, evalResult) =>
    E.chain((msg) =>
        E.chain((eval) =>
            msg && eval ? E.right(true) : E.left(EvaluationAuthorizationFailed(proposition, proof))
        )(evalResult)
    )(msgResult);
