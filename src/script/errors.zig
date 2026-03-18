pub const ScriptError = error{
    Overflow,
    UnsupportedLockingScript,
    InvalidPushData,
    InvalidUnlockingScript,
    StackUnderflow,
    InvalidSignatureEncoding,
    InvalidPublicKeyEncoding,
};
