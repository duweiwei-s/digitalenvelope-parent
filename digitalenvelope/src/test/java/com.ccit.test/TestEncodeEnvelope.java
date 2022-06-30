package com.ccit.test;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import com.ccit.digitalenvelope.asn1structure.FileUtil;
import com.ccit.digitalenvelope.exception.ParameterException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.Test;

import com.ccit.digitalenvelope.EnvelopeUtil;


public class TestEncodeEnvelope {

	/**
	 * 封装数字信封(文件格式)
	 */
	@Test
	public void TestEncodeDigitalEnvelope() {
		EnvelopeUtil enelope = new EnvelopeUtil();

		//接受者证书
		String recipientCert ="MIIClzCCAj2gAwIBAgIIICARBgA4ByAwCgYIKoEcz1UBg3UwbzEaMBgGA1UEAwwRU2hhbkRvbmdTTTJUZXN0Q0ExDTALBgNVBAsMBFNEQ0ExDTALBgNVBAoMBFNEQ0ExEjAQBgNVBAcMCea1juWNl+W4gjESMBAGA1UECAwJ5bGx5Lic55yBMQswCQYDVQQGEwJDTjAeFw0yMDExMDYwOTQ0NDFaFw0yMTA1MDUwOTQ0NDFaMGAxFjAUBgNVBAMMDea1i+ivleivgeS5pjIxHDAaBgNVBAsME0kzNzA3MDIxOTkxMDQyMzQyMTExDjAMBgNVBAcMBWppbmFuMQswCQYDVQQIDAJTRDELMAkGA1UEBgwCQ04wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATd3Ev+c3YCz5evBEWBdIphmDuLnVvE2vn6mh8YujjyCzcJj84LzrvCZ1jpK4V8iiLR1/n7XUcuUrX6nyvPytqho4HRMIHOMB8GA1UdIwQYMBaAFBxdrOHAKs5eSsyj9C8i/6Om8wTOMB0GA1UdDgQWBBQpFWUxTLL9alc7JngZje1RlQVVuzAJBgNVHRMEAjAAMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly8yMjEuMjE0LjUuODA6ODA4OC9TaGFuRG9uZ1NNMlRlc3RDQS9TTTJDUkwuanNwMA4GA1UdDwEB/wQEAwIGwDApBgcqgRyG7zsGBB4MHCAxQDAwMDFTRjAzNzA3MDIxOTkxMDQyMzQyMTEwCgYIKoEcz1UBg3UDSAAwRQIgasoPAMWzpczCdPQbg4pu/GD8G1ph+rAeeMrc5VVp54wCIQCFtxAygnhEvKo7MrXkXdvn7yRadLCQQSXmkOS4r/4RPA==";
		//签名者证书
		String signerCert = "MIIB9TCCAZmgAwIBAgIDBueqMAwGCCqBHM9VAYN1BQAwgYwxCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbljJfkuqwxDzANBgNVBAcMBuWMl+S6rDENMAsGA1UECgwEQ0NJVDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxHDAaBgkqhkiG9w0BCQEWDXVzZXJAdXNlci5jb20xGDAWBgNVBAMMD0NDSVQgU00yIFNVQiBDQTAeFw0yMDExMDgwNDA3MTVaFw0yMTExMDgwNDA3MTVaMCQxCzAJBgNVBAYTAkNOMRUwEwYDVQQDDAznrb7nq6Dkurpyc2EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASKuZdSs17p05Xr2HblpXxkElb8+MUxuFwklKT/K2xpQQE6qUyq5PmucziCjag50QAfHCdKWvyPSngXbgWYUGIko08wTTAfBgNVHSMEGDAWgBSRzLGxrNfv7PN0oPwM1ExHGDVLpTALBgNVHQ8EBAMCAsQwHQYDVR0OBBYEFMBMGRlCffSI114g+Mysu/wkTKW0MAwGCCqBHM9VAYN1BQADSAAwRQIgX0EMSerApoJSGVIVutu1t8UliIFS8H6ayD412qQJHvkCIQCyBUSTlnPNIwN2T74zVbsuEggr12o8Ds4fwpN5aU/akQ==";
		//签名者证书对应私钥
		String keyno = "1";
		//原文读取路径
		String filepath = "D:/项目维护/山东疾控/002.PDF";
		String  digitalenelope=enelope.encodeEnvelopedData(recipientCert,keyno,signerCert, filepath);
		System.out.println(digitalenelope);

	}

        /**
         * 封装数字信封(数据形式)
		 */
        @Test
        public void TestEncodeDigitalEnvelopeData() throws IOException{
            EnvelopeUtil envelope = new EnvelopeUtil();
            //接受者证书
			String recipientCert ="MIIBxzCCAXSgAwIBAgIEAqx4hzAKBggqgRzPVQGDdTA5MQswCQYDVQQGEwJDTjEqMCgGA1UEAwwh56e75Yqo5LqS6IGU572R5a6J5YWo5pyN5Yqh5bmz5Y+wMB4XDTIyMDQwMjA4MTcxNloXDTIzMDQwMjA4MTcxNlowLjELMAkGA1UEBhMCQ04xHzAdBgNVBAMMFjIwMjEwNTIwMTQyNjEwODE1NTA5MTAwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATaGOxgmkMngJN3IJFuK8QHsvFd+aUCk4eIlEZrpr7RycgSzFPIy9yhv7YA+LH7JoO6elTzXTLiROnNonAZPxPvo3UwczBkBgNVHQ4EXQRbMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2hjsYJpDJ4CTdyCRbivEB7LxXfmlApOHiJRGa6a+0cnIEsxTyMvcob+2APix+yaDunpU810y4kTpzaJwGT8T7zALBgNVHQ8EBAMCBsAwCgYIKoEcz1UBg3UDQQDcFmAENK0UO40ZOpZxb+BzSRaXsEKNzh9LTdYn7xnaUvePgR4lGnb7IjZGfEBN0IrExNaqKFj7V/3gy36YOaxs";
			//签名者证书
            String signerCert = "MIIBxzCCAXSgAwIBAgIEAqx4hzAKBggqgRzPVQGDdTA5MQswCQYDVQQGEwJDTjEqMCgGA1UEAwwh56e75Yqo5LqS6IGU572R5a6J5YWo5pyN5Yqh5bmz5Y+wMB4XDTIyMDQwMjA4MTcxNloXDTIzMDQwMjA4MTcxNlowLjELMAkGA1UEBhMCQ04xHzAdBgNVBAMMFjIwMjEwNTIwMTQyNjEwODE1NTA5MTAwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATaGOxgmkMngJN3IJFuK8QHsvFd+aUCk4eIlEZrpr7RycgSzFPIy9yhv7YA+LH7JoO6elTzXTLiROnNonAZPxPvo3UwczBkBgNVHQ4EXQRbMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2hjsYJpDJ4CTdyCRbivEB7LxXfmlApOHiJRGa6a+0cnIEsxTyMvcob+2APix+yaDunpU810y4kTpzaJwGT8T7zALBgNVHQ8EBAMCBsAwCgYIKoEcz1UBg3UDQQDcFmAENK0UO40ZOpZxb+BzSRaXsEKNzh9LTdYn7xnaUvePgR4lGnb7IjZGfEBN0IrExNaqKFj7V/3gy36YOaxs";
            //签名者证书对应私钥
            String keynote = "1";
            //数据原文
            byte[] indicate = "1234567812345678qwertyuiopasdfghjklzxcvbnm".getBytes("GBK");
            String  digitalized=envelope.encodeEnvelopedData(recipientCert,keynote,signerCert,indicate);
            System.out.println(digitalized);

        }

	/**
	 * 解析数字信封(文件格式)
	 */
	@Test
	public void TestDecodeDigitalEnvelope() {

		EnvelopeUtil enelope = new EnvelopeUtil();
		//数字信封读取路径
		String filepath = "E:\\01 工作任务\\01 山东疾控\\从前端读出的加密数据.txt";
		//原文保存路径
		String outpath = "E:\\01 工作任务\\01 山东疾控\\004.pdf";
		//接受者证书对应密钥号
		String keyno = "EccKey1";
		boolean flag=enelope.decodeEnvelopedData(keyno,filepath, outpath);
		System.out.println(flag);

	}


	/**
	 * 解析数字信封(数据格式)
	 */
	@Test
	public void TestDecodeDigitalEnvelopeData() {

		EnvelopeUtil enelope = new EnvelopeUtil();
		//数字信封BASE64格式
		String envelopedData = "MIIEUQYKKoEcz1UGAQQCBKCCBEEwggQ9AgEBMYIBIDCCARwCAQAwQTA5MQswCQYDVQQGEwJDTjEqMCgGA1UEAwwh56e75Yqo5LqS6IGU572R5a6J5YWo5pyN5Yqh5bmz5Y+wAgQCrHiHMBMGByqGSM49AgEGCCqBHM9VAYN1BIG+MIG7BEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKcUNmYoT2OgRsuNa55KVEaHdUEsDZgaIHZjrCHocKP7BEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMWwuc2tL7yIS/gqPlewm0UVXL9+5xmFO9HqgJ2iEINzBCBPeLN+D5IHYKf/FDYaibEAGDp7Gx5x2V8pFiSxniaRWAIBEAQQD6ZJ1KQSO7KRzORwzyw91zEMMAoGCCqBHM9VAYMRMEkGCiqBHM9VBgEEAgEwCQYHKoEcz1UBaIAwWZ3CUVavoJcXIXVx3/B7eGfxModezOrLpAp3ww85QHzrX64wolmHZSmPbRYnDSU8oIIByzCCAccwggF0oAMCAQICBAKseIcwCgYIKoEcz1UBg3UwOTELMAkGA1UEBhMCQ04xKjAoBgNVBAMMIeenu+WKqOS6kuiBlOe9keWuieWFqOacjeWKoeW5s+WPsDAeFw0yMjA0MDIwODE3MTZaFw0yMzA0MDIwODE3MTZaMC4xCzAJBgNVBAYTAkNOMR8wHQYDVQQDDBYyMDIxMDUyMDE0MjYxMDgxNTUwOTEwMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2hjsYJpDJ4CTdyCRbivEB7LxXfmlApOHiJRGa6a+0cnIEsxTyMvcob+2APix+yaDunpU810y4kTpzaJwGT8T76N1MHMwZAYDVR0OBF0EWzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABNoY7GCaQyeAk3cgkW4rxAey8V35pQKTh4iURmumvtHJyBLMU8jL3KG/tgD4sfsmg7p6VPNdMuJE6c2icBk/E+8wCwYDVR0PBAQDAgbAMAoGCCqBHM9VAYN1A0EA3BZgBDStFDuNGTqWcW/gc0kWl7BCjc4fS03WJ+8Z2lL3j4EeJRp2+yI2RnxATdCKxMTWqihY+1f94Mt+mDmsbDGB6zCB6AIBATBBMDkxCzAJBgNVBAYTAkNOMSowKAYDVQQDDCHnp7vliqjkupLogZTnvZHlronlhajmnI3liqHlubPlj7ACBAKseIcwCgYIKoEcz1UBgxEwCgYIKoEcz1UBgi0EgYcwgYQEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqhYp/eZiQqYbwjKIhG0pljfhZooomwQlARNwbEFuU0EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzj+gewvesl8rfuNkH2Ulb29IIWf4K0jmcggeBACWZLE=";
		//接受者证书对应密钥号
		String keyno = "1";
		byte[]  indata=enelope.decodeEnvelopedData_byfileData(keyno,Base64.decode(envelopedData));
		System.out.println("十六进制数据 = "+byteToHex(indata));
		System.out.println("数据 = "+new String(indata));

	}
	/**
	 * 解析数字信封(数据格式内容是文件解密)
	 */
	@Test
	public void TestDecodeDigitalEnvelopeData_byFileData() throws IOException{

		EnvelopeUtil enelope = new EnvelopeUtil();
		//	从数据库中取出的数据 enveploped
		byte[] enveploped=FileUtil.readFileToByte(new File("E:\\01 工作任务\\01 山东疾控\\从前端读出的加密数据 - 副本.txt"));
		//接受者证书对应密钥号
		String keyno = "1";
		byte[]  data=enelope.decodeEnvelopedData_byfileData(keyno,enveploped);
		FileUtil.writeBytesToFile(data, new File("E:\\01 工作任务\\01 山东疾控\\111.pdf"));
		System.out.println(Arrays.toString(data));

	}
	/**
	 * byte数组转hex
	 */
	public static String byteToHex(byte[] bytes){
		String strHex;
		StringBuilder sb = new StringBuilder();
		for (byte aByte : bytes) {
			strHex = Integer.toHexString(aByte & 0xFF);
			sb.append((strHex.length() == 1) ? "0" + strHex : strHex); // 每个字节由两个字符表示，位数不够，高位补0
		}
		return sb.toString().trim();
	}


	/**
	 * 证书验签
	 */
	@Test
	public void TestVerifySign(){
		EnvelopeUtil envelope = new EnvelopeUtil();
		//原文
		byte[] data = "12345678".getBytes();
		//签名值
		byte[] sonata = Base64.decode("MIGEBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJSqEoXqfgLRvo4DgkwOB9niIOCNCSC23Mw8Cst9NrY2BEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOaUZuIf859sez43fNKEjji7nku6mOYxJjiNUnHRYeaP");
		//验签证书
		String cert = "MIIBxzCCAXSgAwIBAgIEAqx4hzAKBggqgRzPVQGDdTA5MQswCQYDVQQGEwJDTjEqMCgGA1UEAwwh56e75Yqo5LqS6IGU572R5a6J5YWo5pyN5Yqh5bmz5Y+wMB4XDTIyMDQwMjA4MTcxNloXDTIzMDQwMjA4MTcxNlowLjELMAkGA1UEBhMCQ04xHzAdBgNVBAMMFjIwMjEwNTIwMTQyNjEwODE1NTA5MTAwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATaGOxgmkMngJN3IJFuK8QHsvFd+aUCk4eIlEZrpr7RycgSzFPIy9yhv7YA+LH7JoO6elTzXTLiROnNonAZPxPvo3UwczBkBgNVHQ4EXQRbMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2hjsYJpDJ4CTdyCRbivEB7LxXfmlApOHiJRGa6a+0cnIEsxTyMvcob+2APix+yaDunpU810y4kTpzaJwGT8T7zALBgNVHQ8EBAMCBsAwCgYIKoEcz1UBg3UDQQDcFmAENK0UO40ZOpZxb+BzSRaXsEKNzh9LTdYn7xnaUvePgR4lGnb7IjZGfEBN0IrExNaqKFj7V/3gy36YOaxs";
		System.out.println(envelope.verifySign(data,sonata,cert));

	}

	/**
	 * 签名
	 */
	@Test
	public void testSigner(){
		EnvelopeUtil envelopeUtil = new EnvelopeUtil();
		byte[] data = "12345678".getBytes();//原文
		String keyNo = "1";//密码机密钥号
		String signer = envelopeUtil.internalPrivateKeySign(keyNo,data);
		System.out.println(signer);

	}

    /**
     * 摘要sm3
     */
    @Test
	public void testSM3Digest(){
        EnvelopeUtil envelopeUtil = new EnvelopeUtil();
        String indata = "北京市北京12345678";
        byte[] digest = envelopeUtil.sm3Digest(indata.getBytes());
        System.out.println(new String (Base64.encode(digest)));
    }

    /**
     * sm2 加密
     */
    @Test
    public void testSM2enc() throws ParameterException {
        EnvelopeUtil envelope = new EnvelopeUtil();
        //原文
        byte[] indata = ("2020111306831613"+"09Csoo9XFTw=").getBytes();
        //加密证书
        String cert = "MIIBxzCCAXSgAwIBAgIEAqx4hzAKBggqgRzPVQGDdTA5MQswCQYDVQQGEwJDTjEqMCgGA1UEAwwh56e75Yqo5LqS6IGU572R5a6J5YWo5pyN5Yqh5bmz5Y+wMB4XDTIyMDQwMjA4MTcxNloXDTIzMDQwMjA4MTcxNlowLjELMAkGA1UEBhMCQ04xHzAdBgNVBAMMFjIwMjEwNTIwMTQyNjEwODE1NTA5MTAwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATaGOxgmkMngJN3IJFuK8QHsvFd+aUCk4eIlEZrpr7RycgSzFPIy9yhv7YA+LH7JoO6elTzXTLiROnNonAZPxPvo3UwczBkBgNVHQ4EXQRbMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2hjsYJpDJ4CTdyCRbivEB7LxXfmlApOHiJRGa6a+0cnIEsxTyMvcob+2APix+yaDunpU810y4kTpzaJwGT8T7zALBgNVHQ8EBAMCBsAwCgYIKoEcz1UBg3UDQQDcFmAENK0UO40ZOpZxb+BzSRaXsEKNzh9LTdYn7xnaUvePgR4lGnb7IjZGfEBN0IrExNaqKFj7V/3gy36YOaxs";
        String cipher = envelope.certEnc(cert,indata);
        System.out.println(cipher);
    }

    /**
     * sm2 解密
     */
    @Test
    public void testSM2dec(){
        EnvelopeUtil envelope = new EnvelopeUtil();
        String keyNO = "1";
        String cipher = "MIHHBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABr6XRGrWZDY50lCWnvoE98WK8Yj1y1k1sna56L+3AmyBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHORKPWbjmIhp5E5IzgrloO+mF/3A+GE9LUuzTPm9HuPBCD6M8k7gqvAybTpeTuohijyp8vxUf/LZ+KUHG3Ka8moXQIBHAQc631bxc70OHQDBfrXuKx4a+sDSnwdNspzQH3eOw==";

        byte[] indata = envelope.internalPrivateKeyDec(keyNO,Base64.decode(cipher));
        System.out.println(new String(indata));
    }

	/**
	 * HMAC-SM3
	 */
	@Test
    public void testSm3HashMac(){
		EnvelopeUtil envelope = new EnvelopeUtil();
		String text = "12345678aaaaa";
		byte[] key = "1234567887654323".getBytes();
		byte[] hmac = envelope.sm3HashMac(text.getBytes(),key);
		System.out.println(new String(Base64.encode(hmac)));
	}


	/**
	 * 龙脉签名值转化成中安云科可以识别的签名值
	 * @throws IOException
	 */
	@Test
	public void testLongToZayk() throws IOException {
		//龙脉签名值
		String signl = "MEQCIHPbSKbGYAl05hbjA0UoCyViJCLT4V4vRrSkAxK+z3o2AiAwm748VKB09hnraXe9aHnsbvty9YtDF+ewY3HdphWHdg==";
		//把龙脉签名值接base64
		byte[] signlby = Base64.decode(signl);
		//解析签名值
		ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(signlby);
		//获取签名值中的r
		ASN1Integer asn1IntegerR = ASN1Integer.getInstance(asn1Sequence.getObjectAt(0));
		//获取签名值中的s
		ASN1Integer asn1IntegerS = ASN1Integer.getInstance(asn1Sequence.getObjectAt(1));
		//签名值中R转化为byte[]
		byte[] signR = BigIntegers.asUnsignedByteArray(asn1IntegerR.getPositiveValue());
		//签名值中S转化为byte[]
		byte[] signS = BigIntegers.asUnsignedByteArray(asn1IntegerS.getPositiveValue());
		//拼接成中安云科可识别的签名值结构
		//拼接R
		byte[] signR_Z = new byte[signR.length+32];
		System.arraycopy(signR,0,signR_Z,32,32);
		//拼接S
		byte[] signS_Z = new byte[signS.length+32];
		System.arraycopy(signS,0,signS_Z,32,32);
		//把中安云科密码机签名值转化成asn1结构
		//转化R成OctetString
		ASN1OctetString asn1OctetStringR = new DEROctetString(signR_Z);
		//转化S成OctetString
		ASN1OctetString asn1OctetStringS = new DEROctetString(signS_Z);
		//拼接成中安云科可识别的签名值asn1结构
		ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
		asn1EncodableVector.add(asn1OctetStringR);
		asn1EncodableVector.add(asn1OctetStringS);
		ASN1Sequence asn1SequenceSign_z = new DERSequence(asn1EncodableVector);
		//得到中安云科可以识别的签名值
		byte[] sign_Z = asn1SequenceSign_z.getEncoded();
		System.out.println("龙脉签名值转化成中安云科可以识别的签名值 结果 ：  "+new String(Base64.encode(sign_Z)));

	}

	/**
	 * 中安云科签名值转化为龙脉可识别的签名值
	 */
	@Test
	public void zaykToLong() throws IOException {

		//中安云科签名值
		String sign_z = "MIGEBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJSqEoXqfgLRvo4DgkwOB9niIOCNCSC23Mw8Cst9NrY2BEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOaUZuIf859sez43fNKEjji7nku6mOYxJjiNUnHRYeaP";
		//把签名值解base64
		byte[] sign_z_b = Base64.decode(sign_z);
		//把签名值转为asn1结构
		//解析签名值
		ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(sign_z_b);
		//获取中安云科签名值R的asn1结构
		ASN1OctetString asn1OctetStringR_z = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(0));
		//获取中安云科签名值S的asn1结构
		ASN1OctetString asn1OctetStringS_z = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(1));
		//签名值中R转化为BigIntegers
		BigInteger bigIntegersR = BigIntegers.fromUnsignedByteArray(asn1OctetStringR_z.getOctets());
		//签名值中S转化为BigIntegers
		BigInteger bigIntegersS = BigIntegers.fromUnsignedByteArray(asn1OctetStringS_z.getOctets());
		//签名值中R转asn1
		ASN1Integer asn1IntegerR = new ASN1Integer(bigIntegersR);
		//签名值中S转asn1
		ASN1Integer asn1IntegerS = new ASN1Integer(bigIntegersS);
		//转龙脉可识别签名值asn1
		ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
		asn1EncodableVector.add(asn1IntegerR);
		asn1EncodableVector.add(asn1IntegerS);
		ASN1Sequence asn1SequenceSign = new DERSequence(asn1EncodableVector);
		byte[] sign = asn1SequenceSign.getEncoded();
		System.out.println("中安云科转化成龙脉可识别的签名值 结果是："+Base64.toBase64String(sign));
	}

	/**
	 * 验证签名测试
	 */
	@Test
	public void verifySign() {
		try {

			String originalText = "Anzxlwsw5mRdJ55JFBYF";
			String signl = "MEQCIHPbSKbGYAl05hbjA0UoCyViJCLT4V4vRrSkAxK+z3o2AiAwm748VKB09hnraXe9aHnsbvty9YtDF+ewY3HdphWHdg==";

			EnvelopeUtil envelope = new EnvelopeUtil();
			//原文
			byte[] data = originalText.getBytes();
			//验签证书
			String cert = "MIIBhzCCAS2gAwIBAgIECO40FzAKBggqgRzPVQGDdTAhMQswCQYDVQQGEwJDTjESMBAGA1UEAwwJU00y5LqM57qnMB4XDTIyMDYyMzAzMjI1M1oXDTIzMDYyMzAzMjI1M1owJTELMAkGA1UEBhMCQ04xFjAUBgNVBAMMDeawuOW3nua1i+ivlTMwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQDirOb5GdfCHmlTyzU6KKLRoeNqOuFQySQ7pRnO0SwZvGOJTeEeopGjGyWkzAagA0PT9cNN/g5SJVE+f+hcVb3o08wTTAfBgNVHSMEGDAWgBSxGlaJI/Fc5w+BjdBM/CqQYvpESzALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFMqBrbJ9BzZEpbdgkMlMI+xnwQFgMAoGCCqBHM9VAYN1A0gAMEUCIQCcF7Nck2kJyNh0zSLUNgQgv1zFk0z54OHPrHmey89CPgIgc2Yyjw35GBrIjcv+1hGa1ZiviI3rP4DjNhdGmKLimnA=";//ConfigurationFactory.getUserLocalConfiguration().getConfigValue("EOS-USER-LOCAL", "ASPOSE-WORDS", "LICENSE");

			byte[] sign_Z = Base64.decode(signl);

			boolean a =  envelope.verifySign(data, sign_Z, cert);
			System.out.println(a);

		}catch(Exception e) {
			e.printStackTrace();
		}
	}






}
