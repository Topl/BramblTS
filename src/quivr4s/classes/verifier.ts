export class Verifier {
    /// Will return [QuivrResult] Left => [QuivrRuntimeError.messageAuthorizationFailure] if the proof is invalid.
    static QuivrResult<bool> _evaluateBlake2b256Bind(
        String tag,
        Proof proof,
        TxBind proofTxBind,
        DynamicContext context,
    ) {
    final sb = context.signableBytes;
    final merge = utf8.encode(tag) + sb.value.toUint8List();
    final verifierTxBind = blake2b256.convert(merge).bytes;

    final result = ListEquality().equals(verifierTxBind, proofTxBind.value.toUint8List());

        return result ? QuivrResult.right(result) : QuivrResult.left(ValidationError.messageAuthorizationFailure());
    }

}