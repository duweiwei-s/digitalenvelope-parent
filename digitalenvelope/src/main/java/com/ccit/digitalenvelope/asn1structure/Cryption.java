package com.ccit.digitalenvelope.asn1structure;


import java.math.BigInteger;

public class Cryption {

	/**
	 * SM2私钥解密接口
	 * @param bytInputData 密文数据
	 * @param bytPridA 私钥
	 * @return 明文
	 */
	public static byte[] SM2Decrypt(byte[] bytInputData, byte[] bytPridA) {

		//presume the input data : [C1(65 Byte)][C2(unknown length)][C3(32 Byte)]
		//presume the input data : [C1(65 Byte)][C3(32 Byte)][C2(unknown length)]
		if (bytInputData == null || bytInputData.length < 98
				|| null == bytPridA || bytPridA.length != 32) {
			ErrCode.mCryptionLastError = ErrCode.CRY_PARAM_ERR;
			return null;
		}
		byte[] C3, dgstC3, C2, pout, tmpX2Buff, tmpY2Buff, ptmp, p;
		int C2Len = bytInputData.length - 65 - 32;
		int iter = 0;

		//compute C3
		C3 = new byte[32];
//		System.arraycopy(bytInputData, C2Len+65, C3, 0, 32);
//		Muesli comment 2013-07-22  src by dongxuefei
		//密文C=c1||c3||c2,取c3起始位置变化
		System.arraycopy(bytInputData, 65, C3, 0, 32);

		BigInteger  big_pri_dA, big_x1, big_y1, big_x2, big_y2,
				big_Xg, big_Yg, big_a, big_b, big_n, big_p;

		big_a = new BigInteger(Constants.SM2_A, 16);
		big_b = new BigInteger(Constants.SM2_B, 16);
		big_n = new BigInteger(Constants.SM2_N, 16);
		big_p = new BigInteger(Constants.SM2_P, 16);
		big_Xg = new BigInteger(Constants.SM2_G_X, 16);
		big_Yg = new BigInteger(Constants.SM2_G_Y, 16);

		C2 = new byte[C2Len];

		/*
		 * step 1: organize C1 and check if C1 on curve
		 */
		byte[] C1 = new byte[64];
		System.arraycopy(bytInputData, 1, C1, 0, 64);
		boolean IsC1OnCurve = EccPoint.IsXYOnSM2Curve(C1);
		if (!IsC1OnCurve) {
			ErrCode.mCryptionLastError = ErrCode.CRY_POINT_NOT_ON_CURVE_ERR;
			return null;
		}

		/*
		 * step 2: check if is infinite point
		 */
		//????????????????????????

		/*
		 * step 3: dA*C1 = dA*(x2,y2) = dA*[k]*(Xg,Yg)
		 */
		big_pri_dA = new BigInteger(Util.ByteArrayToString(bytPridA, 0), 16);

		byte[] bytx1 = new byte[32];
		byte[] byty1 = new byte[32];
		System.arraycopy(C1, 0, bytx1, 0, 32);
		System.arraycopy(C1, 32, byty1, 0, 32);

		big_x1 = new BigInteger(Util.ByteArrayToString(bytx1, 0), 16);
		big_y1 = new BigInteger(Util.ByteArrayToString(byty1, 0), 16);


		BigInteger[] big_x2y2 = EccPoint.EccPointMul(big_x1, big_y1, big_pri_dA, big_a, big_p);
		if (big_x2y2 == null) {
			ErrCode.mCryptionLastError = ErrCode.CRY_POINT_MUL_ERR;
			return null;
		}
		big_x2 = big_x2y2[0];
		big_y2 = big_x2y2[1];

		String strTmpX2Buff = big_x2.toString(16);
		String strTmpY2Buff = big_y2.toString(16);
		if (strTmpX2Buff.length() < 64) {
			for (int i = 0; i < (64-strTmpX2Buff.length()); i++) {
				strTmpX2Buff = "0" + strTmpX2Buff;
			}
		}
		if (strTmpY2Buff.length() < 64) {
			for (int i = 0; i < (64-strTmpY2Buff.length()); i++) {
				strTmpY2Buff = "0" + strTmpY2Buff;
			}
		}
		tmpX2Buff = Util.StringToByteArray(strTmpX2Buff);
		tmpY2Buff = Util.StringToByteArray(strTmpY2Buff);


		/*
		 * step 4: compute t= KDF(x2||y2, klen)
		 */
		ptmp = new byte[tmpX2Buff.length+tmpY2Buff.length];
		System.arraycopy(tmpX2Buff, 0, ptmp, 0, tmpX2Buff.length);
		System.arraycopy(tmpY2Buff, 0, ptmp, tmpX2Buff.length, tmpY2Buff.length);


		pout = KDFwithSm3(ptmp, C2Len);
		if (pout == null) {
			return null;
		}

		//check if t is zero
		for (iter = 0; iter < C2Len; iter++) {
			if(pout[iter] != 0) {
				break;
			}
		}

		if (C2Len == iter)
		{
			ErrCode.mCryptionLastError = ErrCode.CRY_DECRYPT_FAILED_ERR;
			return null;
		}


		/*
		 *  step 5: compute M'=C2^t;
		 */
		for (iter = 0; iter < C2Len; iter++)
		{
//			C2[iter] = (byte) (pout[iter] ^ bytInputData[65+iter]);
//			xueli comment 2013-07-22 src by dongxuefei
//			密文C=c1||c3||c2,取c2起始位置变化
			C2[iter] = (byte) (pout[iter] ^ bytInputData[65+32+iter]);
		}


		/*
		 * step 6: compute C3 = HASH(x2|| M || y2)
		 */

		ptmp = new byte[C2Len+tmpX2Buff.length+tmpY2Buff.length];
		System.arraycopy(tmpX2Buff, 0, ptmp, 0, tmpX2Buff.length);
		System.arraycopy(C2, 0, ptmp, tmpX2Buff.length, C2Len);
		System.arraycopy(tmpY2Buff, 0, ptmp, tmpX2Buff.length+C2Len, tmpY2Buff.length);

		dgstC3 = SM3Hash.GetHashValue(ptmp);
		if (dgstC3 == null) {
			ErrCode.mCryptionLastError = ErrCode.CRY_C3_HASH_ERR;
			return null;
		}

		//check if u=C3
		for (int i = 0; i < 32; i++) {
			if (dgstC3[i] != C3[i]) {
				ErrCode.mCryptionLastError = ErrCode.CRY_DECRYPT_FAILED_ERR;
				return null;
			}
		}
		return C2;
	}

	/*
	 * KDF运算，内部接口
	 */
	private static byte[] KDFwithSm3(byte[] bytZIn, int iKlen) {
		if (bytZIn == null || iKlen == 0) {
			ErrCode.mCryptionLastError = ErrCode.CRY_KDF_PARAM_ERR;
			return null;
		}

		int ct = 1;

		byte[] kdfOutBuff = new byte[iKlen];
		byte[] tmpKdfOutBuff = null;

		byte[] ZandCt = new byte[bytZIn.length+4];//4是ct转化成byte数组之后的长度


		int mod = (iKlen)%32;// 32 = output byte length of sm3 
		int max_iter = iKlen/32;

		byte[] ct_un_buff = null;
		byte[] tmp_buff = new byte[32];

		for (ct = 1; ct <= max_iter; ct++) {
			ct_un_buff = Util.Int2ByteArray(ct, 4);
			if (ct_un_buff == null) {
				ErrCode.mCryptionLastError = ErrCode.CRY_KDF_CT_TRANS_ERR;
				return null;
			}

			System.arraycopy(bytZIn, 0, ZandCt, 0, bytZIn.length);
			System.arraycopy(ct_un_buff, 0, ZandCt, bytZIn.length, ct_un_buff.length);

			tmpKdfOutBuff = SM3Hash.GetHashValue(ZandCt);
			if (tmpKdfOutBuff == null) {
				ErrCode.mCryptionLastError = ErrCode.CRY_KDF_ZCT_HASH_ERR;
				return null;
			}

			System.arraycopy(tmpKdfOutBuff, 0, kdfOutBuff, (ct-1)*32, tmpKdfOutBuff.length);
		}

		ct_un_buff = Util.Int2ByteArray(ct, 4);
		if (ct_un_buff == null) {
			ErrCode.mCryptionLastError = ErrCode.CRY_KDF_CT_TRANS_ERR;
			return null;
		}

		System.arraycopy(bytZIn, 0, ZandCt, 0, bytZIn.length);
		System.arraycopy(ct_un_buff, 0, ZandCt, bytZIn.length, ct_un_buff.length);

		tmp_buff = SM3Hash.GetHashValue(ZandCt);
		if (tmp_buff == null) {
			ErrCode.mCryptionLastError = ErrCode.CRY_KDF_ZCT_HASH_ERR;
			return null;
		}
		System.arraycopy(tmp_buff, 0, kdfOutBuff, (ct-1)*32, mod);

		return kdfOutBuff;
	}

}
