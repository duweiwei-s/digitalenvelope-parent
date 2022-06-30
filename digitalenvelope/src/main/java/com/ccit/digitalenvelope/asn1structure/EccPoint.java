package com.ccit.digitalenvelope.asn1structure;


import java.math.BigInteger;




/**
 * @author 作者 :董学飞
 * @version 创建时间：2013-3-9 下午7:39:47
 */
public class EccPoint {

	/**
	 * 符合椭圆曲线运算规则的点加接口
	 * @param X1
	 * @param Y1
	 * @param X2
	 * @param Y2
	 * @param a 椭圆曲线参数
	 * @param p 椭圆曲线参数
	 * @return (X1+X2, Y1+Y2)
	 */
	public static BigInteger[] EccPointAdd(BigInteger X1, BigInteger Y1,
										   BigInteger X2, BigInteger Y2, BigInteger a, BigInteger p) {
		if (X1.equals(null) || Y1.equals(null)
				|| X2.equals(null) || Y2.equals(null)
				|| a.equals(null) || p.equals(null)) {
			ErrCode.mEccPointLastError = ErrCode.ECC_BIG_PARAM_ERR;
			return null;
		}
		BigInteger tmp_r;
		BigInteger tmp1, tmp2;
		BigInteger Lambda;
		BigInteger top, bottom;

		BigInteger[] resultXY = new BigInteger[2];

		// P(x1,y1); Q(x2,y2); x1=y1=x2=y2=0; so: P+Q==0
		if ((X1.equals(BigInteger.ZERO) && Y1.equals(BigInteger.ZERO))
				&& (X2.equals(BigInteger.ZERO) && Y2.equals(BigInteger.ZERO))) {
			resultXY[0] = BigInteger.ZERO;
			resultXY[1] = BigInteger.ZERO;
			return resultXY;
		}

		if (X1.equals(BigInteger.ZERO) && Y1.equals(BigInteger.ZERO)) {
			resultXY[0] = X2;
			resultXY[1] = Y2;
			return resultXY;
		}

		if (X2.equals(BigInteger.ZERO) && Y2.equals(BigInteger.ZERO)) {
			resultXY[0] = X1;
			resultXY[1] = Y1;
			return resultXY;
		}

		// P(x,y); Q(x,-y); P+Q==0
		tmp_r = BigInteger.ZERO;
		tmp_r = Y1.add(Y2);

		if (X1.equals(X2) && tmp_r.equals(BigInteger.ZERO)) {
			resultXY[0] = BigInteger.ZERO;
			resultXY[1] = BigInteger.ZERO;
			return resultXY;
		}

		tmp1 = BigInteger.ZERO;
		tmp2 = BigInteger.ZERO;

		// P+Q!=0 : compute Lambda
		Lambda = BigInteger.ZERO;
		top = BigInteger.ZERO;
		bottom = BigInteger.ZERO;

		if (X1.equals(X2)) {// x1==x2 and P+Q != 0 : lambda=(3*x1^2+a)/2*y1
			tmp1 = X1.multiply(X1);
			tmp2 = tmp1.add(tmp1).add(tmp1);// tmp2 = tmp1*3
			top = tmp2.add(a).mod(p);// //top = 3*x1^2+a
			tmp1 = Y1.add(Y1);
			// bottom = tmp1.pow(-1).mod(p);////bottom = 1/2*y1
			bottom = tmp1.modInverse(p);// 替换上面这行
			Lambda = top.multiply(bottom).mod(p);
		} else {// x1 != x2 :lambda=(y2-y1)/(x2-x1)
			top = Y2.add(Y1.negate()).mod(p);
			tmp1 = X2.add(X1.negate()).mod(p);
			// bottom = tmp1.pow(-1).mod(p);//bottom = 1/(x2-x1)
			bottom = tmp1.modInverse(p);// 替换上面这行
			Lambda = top.multiply(bottom).mod(p);

		}

		// x3 = lambda^2-x1-x2
		tmp1 = Lambda.multiply(Lambda);
		tmp2 = tmp1.add(X1.negate());
		resultXY[0] = tmp2.add(X2.negate()).mod(p);

		// y3 = lambda*(x1-x3) - y1
		tmp1 = X1.add(resultXY[0].negate());
		tmp2 = Lambda.multiply(tmp1);
		resultXY[1] = tmp2.add(Y1.negate()).mod(p);

		return resultXY;
	}

	/**
	 * 符合椭圆曲线运算规则的点乘接口
	 * @param Px
	 * @param Py
	 * @param d
	 * @param a 椭圆曲线参数
	 * @param p 椭圆曲线参数
	 * @return d(Px, Py)
	 */
	public static BigInteger[] EccPointMul(BigInteger Px, BigInteger Py,
										   BigInteger d, BigInteger a, BigInteger p) {

		if (Px.equals(null) || Py.equals(null)
				|| d.equals(null) || a.equals(null)
				|| p.equals(null)) {
			ErrCode.mEccPointLastError = ErrCode.ECC_BIG_PARAM_ERR;
			return null;
		}
		BigInteger[] resultXY = new BigInteger[2];
		BigInteger A, P;
		BigInteger Qx, Qy;
		BigInteger tmp_Qx, tmp_Qy;

		A = a;
		P = p;

		Qx = BigInteger.ZERO;// Q: infinite point , or say :Zero point
		Qy = BigInteger.ZERO;
		tmp_Qx = BigInteger.ZERO;
		tmp_Qy = BigInteger.ZERO;

		byte[] bytD = d.toByteArray();
		boolean[] tmp_d = new boolean[bytD.length * 8];
		for (int i = 0; i < bytD.length; i++) {
			if ((bytD[i] & 0x80) == 0x80) {
				tmp_d[8 * i] = true;
			} else {
				tmp_d[8 * i] = false;
			}
			if ((bytD[i] & 0x40) == 0x40) {
				tmp_d[8 * i + 1] = true;
			} else {
				tmp_d[8 * i + 1] = false;
			}
			if ((bytD[i] & 0x20) == 0x20) {
				tmp_d[8 * i + 2] = true;
			} else {
				tmp_d[8 * i + 2] = false;
			}
			if ((bytD[i] & 0x10) == 0x10) {
				tmp_d[8 * i + 3] = true;
			} else {
				tmp_d[8 * i + 3] = false;
			}
			if ((bytD[i] & 0x08) == 0x08) {
				tmp_d[8 * i + 4] = true;
			} else {
				tmp_d[8 * i + 4] = false;
			}
			if ((bytD[i] & 0x04) == 0x04) {
				tmp_d[8 * i + 5] = true;
			} else {
				tmp_d[8 * i + 5] = false;
			}
			if ((bytD[i] & 0x02) == 0x02) {
				tmp_d[8 * i + 6] = true;
			} else {
				tmp_d[8 * i + 6] = false;
			}
			if ((bytD[i] & 0x01) == 0x01) {
				tmp_d[8 * i + 7] = true;
			} else {
				tmp_d[8 * i + 7] = false;
			}
		}

		for (int i = 0; i < tmp_d.length; i++) {
			// Q = [2]Q;
			BigInteger[] tmp_Qxy = EccPointAdd(Qx, Qy, Qx, Qy, A, P);
			if (tmp_Qxy == null) {
				return null;
			}
			tmp_Qx = tmp_Qxy[0];
			tmp_Qy = tmp_Qxy[1];

			if (tmp_d[i]) {// Q = Q + P
				BigInteger[] Qxy = EccPointAdd(tmp_Qx, tmp_Qy, Px, Py, A, P);
				if (Qxy == null) {
					return null;
				}
				Qx = Qxy[0];
				Qy = Qxy[1];

				tmp_Qx = Qx;
				tmp_Qy = Qy;
			}

			Qx = tmp_Qx;
			Qy = tmp_Qy;

		}

		resultXY[0] = tmp_Qx;
		resultXY[1] = tmp_Qy;

		return resultXY;
	}

	/**
	 * 判断某点(x, y)是否在椭圆曲线上
	 * @param big_x 要进行判断的参数
	 * @param big_y 要进行判断的参数
	 * @param big_a 椭圆曲线参数
	 * @param big_b 椭圆曲线参数
	 * @param big_p 椭圆曲线参数
	 * @return true：在曲线上      false：不在曲线上
	 */
	public static boolean IsXYOnSM2Curve(BigInteger big_x, BigInteger big_y,
										 BigInteger big_a, BigInteger big_b, BigInteger big_p) {

		if (big_x.equals(null) || big_y.equals(null)
				|| big_a.equals(null) || big_b.equals(null)
				|| big_p.equals(null)) {
			ErrCode.mEccPointLastError = ErrCode.ECC_BIG_PARAM_ERR;
			return false;
		}

		if (big_x.equals(BigInteger.ZERO) && big_y.equals(BigInteger.ZERO)) {
			ErrCode.mEccPointLastError = ErrCode.ECC_INFINITE_POINT_ERR;
			return false;
		}

		if (!(big_x.compareTo(BigInteger.ZERO) >= 0
				&& big_x.compareTo(big_p) < 0
				&& big_y.compareTo(BigInteger.ZERO) >= 0
				&& big_y.compareTo(big_p) < 0)) {
			ErrCode.mEccPointLastError = ErrCode.ECC_POINT_NOT_ON_CURVE_ERR;
			return false;
		}

		BigInteger left, right, big_tmp1, big_tmp2;

		left = big_y.multiply(big_y).mod(big_p);// y^2
		big_tmp1 = big_x.multiply(big_x).multiply(big_x);// x^3

		big_tmp2 = big_x.multiply(big_a);// a*x
		big_tmp1 = big_tmp1.add(big_tmp2);

		right = big_tmp1.add(big_b).mod(big_p);// x^3 + a*x + b (mod p)

		if (left.compareTo(right) != 0) {
			ErrCode.mEccPointLastError = ErrCode.ECC_POINT_NOT_ON_CURVE_ERR;
			return false;
		}

		return true;
	}

	/**
	 * 判断密钥数据的x、y参数是否在椭圆曲线上
	 * @param pubKey 密钥数据
	 * @return true：在曲线上       false：不在曲线上
	 */
	public static boolean IsXYOnSM2Curve(byte[] pubKey) {

		if (pubKey == null || pubKey.length != 64) {
			ErrCode.mEccPointLastError = ErrCode.ECC_PARAM_ERR;
			return false;
		}

		BigInteger big_a, big_b, big_p, big_x, big_y;
		byte[] bytX = new byte[32];
		byte[] bytY = new byte[32];

		big_a = new BigInteger(Constants.SM2_A, 16);
		big_b = new BigInteger(Constants.SM2_B, 16);
		big_p = new BigInteger(Constants.SM2_P, 16);

		System.arraycopy(pubKey, 0, bytX, 0, 32);
		System.arraycopy(pubKey, 32, bytY, 0, 32);

		big_x = new BigInteger(Util.ByteArrayToString(bytX, 0), 16);
		big_y = new BigInteger(Util.ByteArrayToString(bytY, 0), 16);

		return IsXYOnSM2Curve(big_x, big_y, big_a, big_b, big_p);
	}

}
