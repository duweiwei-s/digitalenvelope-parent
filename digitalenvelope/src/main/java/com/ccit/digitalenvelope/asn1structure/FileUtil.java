package com.ccit.digitalenvelope.asn1structure;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


public class FileUtil {

	public static byte[] readFileToByte(File f) throws IOException{
		byte buff[] = new byte[(int) f.length()];
		FileInputStream in = null;
		try {
			in = new FileInputStream(f);
			in.read(buff);
		} catch (IOException e) {
			throw e;
		} finally {
			if (in != null)
				in.close();
		}
		return buff;
	}

	public static void writeBytesToFile(byte[] indata,File f) throws IOException{
		OutputStream out = new FileOutputStream(f);
		InputStream is = new ByteArrayInputStream(indata);
		byte[] buff = new byte[1024];
		int len = 0;
		while((len=is.read(buff))!=-1){
			out.write(buff, 0, len);
		}
		is.close();
		out.close();
	}


}
