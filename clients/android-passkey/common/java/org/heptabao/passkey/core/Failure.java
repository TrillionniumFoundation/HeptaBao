package org.heptabao.passkey.core;

/** Deliberately fixed failure codes: never include caller JSON or key material. */
public final class Failure extends Exception {
    public final String code;
    public Failure(String code) { super(code); this.code = code; }
    public static void require(boolean accepted, String code) throws Failure {
        if (!accepted) throw new Failure(code);
    }
}
