package com.ccit.digitalenvelope.asn1structure;



public class Util {

	/*
	 * 将十六进制字符串转成byte数组
	 */
	public static byte[] StringToByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return b;
	}

	/*
	 * 将byte数组转成十六进制字符串
	 */
	public static String ByteArrayToString(byte[] b, int start) {
		StringBuffer s = new StringBuffer();
		for (int i = start; i < b.length; i++) {
			s.append(Integer.toHexString(0x100 + (b[i] & 0xff)).substring(1));
		}
		return s.toString();
	}

	public static byte[] Int2ByteArray(int iSource, int iArrayLen) {
		byte[] bLocalArr = new byte[iArrayLen];
		for ( int i = 0; (i < 4) && (i < iArrayLen); i++) {
			bLocalArr[iArrayLen-i-1] = (byte)( iSource>>8*i & 0xFF );

		}
		return bLocalArr;
	}

	// 将byte数组bRefArr转为一个整数,字节数组的低位是整型的低字节位
	public static int ByteArray2Int(byte[] bRefArr) {
		int iOutcome = 0;
		byte bLoop;

		for ( int i =0; i<bRefArr.length ; i++) {
			bLoop = bRefArr[i];
			iOutcome+= (bLoop & 0xFF) << (8 * i);

		}

		return iOutcome;
	}

	public  static String toHexString(byte[] data) {
		byte temp;
		int n;
		String str = "";
		for (int i = 1; i <= data.length; i++) {
			temp = data[i-1];
			n = (int) ((temp & 0xf0) >> 4);
			str += IntToHex(n);
			n = (int) ((temp & 0x0f));
			str += IntToHex(n);
			str += " ";
			if (i % 16 == 0) {
				str += "\n";
			}
		}

		return str;
	}

	public  static void printWithHex(byte[] data) {
		System.out.println(toHexString(data));
	}

	public static String IntToHex(int n) {
		if (n > 15 || n < 0) {
			return "";
		} else if ((n >= 0) && (n <= 9)) {
			return "" + n;
		} else {
			switch (n) {
				case 10: {
					return "A";
				}
				case 11: {
					return "B";
				}
				case 12: {
					return "C";
				}
				case 13: {
					return "D";
				}
				case 14: {
					return "E";
				}
				case 15: {
					return "F";
				}
				default:
					return "";
			}
		}
	}

	public static byte[] IntToByte1(int num) {
		byte[] bytes = new byte[4];

		bytes[0] = (byte)(0xff&(num>>0));
		bytes[1] = (byte)(0xff&(num>>8));
		bytes[2] = (byte)(0xff&(num>>16));
		bytes[3] = (byte)(0xff&(num>>24));

		return bytes;
	}
	public static byte[] intToByte(int i) {
		byte[] temp1 = new byte[4];
		//byte[] temp1 = new byte[j];
		temp1[3] = (byte) (0xff & i);
		temp1[2] = (byte) ((0xff00 & i) >> 8);
		temp1[1] = (byte) ((0xff0000 & i) >> 16);
		temp1[0] = (byte) ((0xff000000 & i) >> 24);

		return temp1;
	}

	public static int bytesToInt(byte[] bytes) {
		int num = 0;
		int temp;
		temp = (0x000000ff & (bytes[0]))<<0;
		num = num | temp;
		temp = (0x000000ff & (bytes[1]))<<8;
		num = num | temp;
		temp = (0x000000ff & (bytes[2]))<<16;
		num = num | temp;
		temp = (0x000000ff & (bytes[3]))<<24;
		num = num | temp;

		return num;
	}

	public static int bigBytesToInt(byte[] in) {
		byte[] out = new byte[in.length];
		for(int i=0; i<out.length; i++) {
			out[i] = in[out.length-i-1];

		}
		int temp2 = bytesToInt(out);


		return temp2;
	}

}
