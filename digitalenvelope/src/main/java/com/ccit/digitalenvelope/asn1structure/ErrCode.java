package com.ccit.digitalenvelope.asn1structure;


public class ErrCode {
    public static int mSignatureLastError = -1;
    public static int mCryptionLastError = -1;
    public static int mKeyPairLastError = -1;
    public static int mEccPointLastError = -1;

    public static int SUCCESS = 0;

    public static int SIG_PARAM_ERR = 1;
    public static int SIG_R_OUTBOUND_ERR = 2;
    public static int SIG_S_OUTBOUND_ERR = 3;
    public static int SIG_T_ZERO_ERR = 4;
    public static int SIG_R_r_DIFFERENT_ERR = 5;
    public static int SIG_GET_E_ERR = 6;
    public static int SIG_BIG_PARAM_ERR = 7;
    public static int SIG_GET_E_PARAM_ERR = 8;
    public static int SIG_GET_E_HASH_ZA_ERR = 9;
    public static int SIG_GET_E_HASH_E_ERR = 10;

    public static int ECC_PARAM_ERR = 21;
    public static int ECC_BIG_PARAM_ERR = 22;
    public static int ECC_INFINITE_POINT_ERR = 23;
    public static int ECC_POINT_NOT_ON_CURVE_ERR = 24;

    public static int KEY_GENKEY_BIG_PARAM_ERR = 31;
    public static int KEY_GENKEY_FAILED_ERR = 32;
    public static int KEY_GENKEY_POINT_MUL_ERR = 33;
    public static int KEY_GENKEY_POINT_NOT_ON_CURVE_ERR = 34;

    public static int CRY_PARAM_ERR = 41;
    public static int CRY_DECRYPT_FAILED_ERR = 42;
    public static int CRY_POINT_MUL_ERR = 43;
    public static int CRY_C3_HASH_ERR = 44;
    public static int CRY_POINT_NOT_ON_CURVE_ERR = 45;
    public static int CRY_KDF_PARAM_ERR = 46;
    public static int CRY_KDF_CT_TRANS_ERR = 47;
    public static int CRY_KDF_ZCT_HASH_ERR = 48;



    public static int UNKNOWN_ERR = 1000;

    public static int GetSignatureLastError() {
        return mSignatureLastError;
    }

    public static int GetCryptionLastError() {
        return mCryptionLastError;
    }

    public static int GetKeyPairLastError() {
        return mKeyPairLastError;
    }

    public static int GetEccPointLastError() {
        return mEccPointLastError;
    }
}
