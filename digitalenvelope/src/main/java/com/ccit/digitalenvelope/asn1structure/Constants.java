package com.ccit.digitalenvelope.asn1structure;

/**
 * @author duwei
 */
public class Constants {
	/**
	 * SM2算法OID
	 */
	public static String SM2_SIG_OID="1.2.156.10197.1.501";
	/*
	 * 大于3的一个素数
	 */
	public static String SM2_P = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

	/*
	 * 用来定义一条曲线的两个参数   ：y2 = x3 + ax + b
	 */
	public static String SM2_A = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
	public static String SM2_B = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

	/*
	 * 基点G的阶
	 */
	public static String SM2_N = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

	/*
	 * 椭圆曲线的一个基点，其阶是素数
	 */
	public static String SM2_G_X = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	public static String SM2_G_Y = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

	/*
	 * 用户标识
	 */
	public static String UserID = "1234567812345678";

	/*
	 * 用来测试的随机数、杂凑值以及私钥数据
	 */
	public static String rand_k = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
	public static String dgst   = "B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76";
	public static String pri_dA = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

	public static String P12_CERT = "p12cert";
	public static String P12_PINCODE = "p12pincode";
//	public static String SM2_P = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
//	public static String SM2_A = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
//	public static String SM2_B = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
//	public static String SM2_N = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
//	public static String SM2_G_X = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
//	public static String SM2_G_Y = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
//	public static String UserID = "1234567812345678";

}
