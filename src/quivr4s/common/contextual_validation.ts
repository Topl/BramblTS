export abstract class ContextualValidation<T, Context> {
    /// Determines the validity of the given value, within some context.
    /// (i.e. if T is a Transaction, there is context about the sequence of transactions leading up to the given `t`)
    abstract validate(context: Context, t: T): T | undefined;
}
