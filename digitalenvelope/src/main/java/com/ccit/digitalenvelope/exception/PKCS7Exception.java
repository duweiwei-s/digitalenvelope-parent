package com.ccit.digitalenvelope.exception;

public class PKCS7Exception extends Exception {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public PKCS7Exception() {
        super();
    }

    public PKCS7Exception(String msg) {
        super(msg);
    }

    public PKCS7Exception(String msg, Throwable cause) {
        super(msg, cause);
    }

    public PKCS7Exception(Throwable cause) {
        super(cause);
    }
}