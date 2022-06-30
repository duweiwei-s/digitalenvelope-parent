import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class ZAYKJCETest {

    //定义数据包长度
    static int datalen = 0;

    static int defaultlen = 100;
    
    public static byte[] plain = null;

    public static int getInput(String promptString, int type) {
        int out = 0, i = 0;
        try {
            byte[] inchar = new byte[10];
            System.out.print(promptString);
            System.in.read(inchar, 0, 10);
            if ((inchar[0] == 10) || (inchar[0] == 0x0d)) {
                if (type == 1)
                    return defaultlen;
                else if (type == 2)
                    return 0;
                else
                    return -1;
            }
            out = Integer.parseInt((new String(inchar)).trim());
        } catch (Exception ee) {
            //ee.printStackTrace();
            return -1;
        }
        return out;
    }

    public static void main(String[] args) {

        datalen = 0;
        while ((datalen < 1) || (datalen > 50 * 1024))
            datalen = getInput("Please input the data length(default is "+defaultlen+"):",
                    1);
        defaultlen = datalen;
        while (true) {
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            System.out.println("++++++++++++++++++++ ZAYKProvider API Test (Hardware) +++++++++++++++++++++");
            System.out.println("                                                                           ");
            System.out.println(" 1 ZAYKProvider ECC Test                                                   ");
            System.out.println("                                                                           ");
            System.out.println(" 2 ZAYKProvider RSA Test                                                   ");
            System.out.println("                                                                           ");
            System.out.println(" 3 ZAYKProvider Symmetry Test                                              ");
            System.out.println("                                                                           ");
            System.out.println(" 4 SM3Test                                                                 ");
            System.out.println("                                                                           ");
            System.out.println(" 5 Random                                                                  ");
            System.out.println("                                                                           ");
            System.out.println(" 0 Exit                                                                    ");
            System.out.println("                                                                           ");
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            int choice = getInput("Select:", 3);
            if (choice == 0) {
                return;
            }
            if ((choice < 1) || (choice > 8))
                continue;
            switch (choice) {
            case 1:
            	TestSM2Func();
                break;
                
            case 2:
                TestRSAFunc();
                break;
                
            case 3:
            	TestSM1SM4Func();
                break;
                
            case 4:
                SM3();
                break;
                
            case 5:
                Random();
                 break;
            }
        }
    }

    public static void TestSM2Func() {
        while (true) {
            System.out.println("++++++++++++++++++ ZAYKProvider API Function Test +++++++++++++++++++++++++");
            System.out.println("                                                                           ");
            System.out.println(" 1 Generate SM2 Keypair                2 SM2 Encrypt and Decrypt           ");
            System.out.println("                                                                           ");
            System.out.println(" 3 SM2 Sign and Verify                 4 SM2 Wrap And UnWrap               ");
            System.out.println("                                                                           ");
            System.out.println(" 0 Return to Main Menu                                                     ");
            System.out.println("                                                                           ");
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            int choice = getInput("Select:", 3);
            if (choice == 0)
                return;
            if ((choice < 1) || (choice > 4))
                continue;
            plain = new byte[datalen];
            for(int i = 0 ; i < datalen; i++)
                plain[i] = (byte)choice;
            try {
                switch (choice) {
                case 1:
                    TestSM2KeyGenFunc();
                    break;
                case 2:
                    TestSM2EncDecFunc();
                    break;
                case 3:
                    TestSM2SignVerFunc();
                    break; 
                case 4:
                	TestSM2WrapUnwrapFunc();
                    break; 
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                continue;
            }
        }
    }

    public static void TestSM1SM4Func() {
        while (true) {
            System.out.println("++++++++++++++++++ ZAYKProvider API Function Test +++++++++++++++++++++++++");
            System.out.println("                                                                           ");
            System.out.println(" 1 SM1/SM4 Encrypt and Decrypt                                             ");
            System.out.println("                                                                           ");
            System.out.println(" 0 Return to Main Menu                                                     ");
            System.out.println("                                                                           ");
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            int choice = getInput("Select:", 3);
            if (choice == 0)
                return;
            if ((choice < 1) || (choice > 5))
                continue;
            plain = new byte[datalen];
            for(int i = 0 ; i < datalen; i++)
                plain[i] = (byte)choice;
            try {
                switch (choice) {
                case 1:
                    TestSMEncDecFunc();
                    break;
               // case 6:
               //     ModifyParameters();
                //    break;   
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                continue;
            }
        }
    }
    public static void TestRSAFunc() {
        while (true) {
            System.out.println("++++++++++++++++++ ZAYKProvider API Function Test +++++++++++++++++++++++++");
            System.out.println("                                                                           ");
            System.out.println(" 1 Generate RSA Keypair                2 RSA Encrypt and Decrypt           ");
            System.out.println("                                                                           ");
            System.out.println(" 3 RSA Sign and Verify                 4 RSA Wrap And UnWrap               ");
            System.out.println("                                                                           ");
            System.out.println(" 0 Return to Main Menu                                                     ");
            System.out.println("                                                                           ");
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            int choice = getInput("Select:", 3);
            if (choice == 0)
                return;
            if ((choice < 1) || (choice > 4))
                continue;
            plain = new byte[datalen];
            for(int i = 0 ; i < datalen; i++)
                plain[i] = (byte)choice;
            try {
                switch (choice) {
                case 1:
                    TestRSAKeyGenFunc();
                    break;
                case 2:
                    TestRSAEncDecFunc();
                    break;
                case 3:
                    TestRSASignVerFunc();
                    break;
                case 4:
                    TestRSAWrapUnwrapFunc();
                    break;   
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                continue;
            }
        }
    }
    
    
    public static void TestSM2KeyGenFunc() {
        int keynum = -1;
        int keylength = -1;
        while( (keynum<0) || (keynum>99) )
            keynum = getInput("Please Input the KeyNumber (0-99) :", 3);

        try
        {
            System.out.print("Create SM2 index=" + keynum);


            //KeyPairGenerator.getInstance(algorithm,provider)
            //参数说明：
            //algorithm：设置算法类型，国密为“SM2”。
            //provider：JCE提供者的名字，中安云科名称为“ZAYKProvider”
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2","ZAYKProvider");

            //initialize(keysize,random)
            //初始化密钥对生成器
            //参数说明：
            //keysize：0：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
              }
              else
              {
                //生成密钥成功。
                System.out.println("ok！");
              }
              PublicKey test= kr.getPublic();
              byte[] aa= test.getEncoded();
              
              System.out.println("SM2 PublicKey="+new String(Base64.encode(aa)));
              System.out.println("ECC Public Key Encode end!");
            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    
    public static void TestSM2EncDecFunc() {
        int keynum = -1;
        int keylength = -1;
        KeyPair kr = null;
        

        while( (keynum<0) || (keynum>99))
            keynum = getInput("Please Input the KeyNumber (0--99) :", 3);

        try
        {
            //KeyPairGenerator.getInstance(algorithm,provider)
            //参数说明：
            //algorithm：设置算法类型，国密为“SM2”。
            //provider：JCE提供者的名字，中安云科名称为“ZAYKProvider”
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2","ZAYKProvider"); // ??----------

            //initialize(keysize,random)
            //初始化密钥对生成器
            //参数说明：
            //keysize：0：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(keynum, new SecureRandom());
           
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
                System.out.println("Gen Ecc KeyPair Error!");
                return;
              }
              else
              {
                //生成密钥成功。
                System.out.println("ok！");
              }
            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
              return;
            }
            
            try
            {

            	Cipher encCipher = Cipher.getInstance("SM2/ECB/Raw", "ZAYKProvider");
                        

                encCipher.init(Cipher.ENCRYPT_MODE, kr.getPublic());
                //doFinal(content)
                //通过调用对content中的内容进行加密。
                //返回值：加密后的结果。

                byte[] encData = encCipher.doFinal("sfo	23jrwmfsafo23rmwelfmewf".getBytes());
    			System.out.println("SM2 EncData = " + Base64.encode(encData));
                if (encData == null)
                {
                    System.out.println("Ecc PKCS1Padding Mode Encrypt ERROR! Return value is NULL!");
                }else
                {
                    //定义解密Cipher类对象
                 	Cipher decCipher = Cipher.getInstance("SM2/ECB/Raw", "ZAYKProvider"); // ??----------
                     
                    //初始化Cipher类对象
                    decCipher.init(Cipher.DECRYPT_MODE, kr.getPrivate());
                    //调用解密函数
                    

                    byte[] tResult = decCipher.doFinal(encData);
                    System.out.println("SM2 Dec : " + new String(tResult));
                    if (tResult == null)
                    {
                        System.out.println("SM2 PKCS1Padding Mode Decrypt ERROR! Return value is NULL!");
                    }      
                     if (Arrays.areEqual("sfo	23jrwmfsafo23rmwelfmewf".getBytes(),tResult))
                        System.out.println("SM2 PKCS1Padding Mode Encrypt and Decrypt Success!");
                      else
                        System.out.println("SM2 PKCS1Padding Mode Encrypt and Decrypt ERROR!");
                }
            }
            catch(Exception e)
            {
                System.out.println("SM2 PKCS1Padding Mode Encrypt and Decrypt ERROR!"+e.getMessage());
                e.printStackTrace();
            }
          
        }
        catch(Exception e)
        {
            System.out.println("Ecc Encrypt and Decrypt ERROR!");
            e.printStackTrace();
        }
    }
   
    public static void TestSM2SignVerFunc() {
        int keynum = -1;
        int keylength = -1;
        while( (keynum<0) || (keynum>99) )
            keynum = getInput("Please Input the KeyNumber (0--99) :", 3);

        try
        {
            //KeyPairGenerator.getInstance(algorithm,provider)
            //参数说明：
            //algorithm：设置算法类型，国密为“SM2”。
            //provider：JCE提供者的名字，中安云科名称为“ZAYKProvider”
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2","ZAYKProvider");// ??----------
            
            //initialize(keysize,random)
            //初始化密钥对生成器
            //参数说明：
            //keysize：0：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {
              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
                System.out.println("Gen ECC KeyPair Error!");
                return;
              }
              else
              {
                //生成密钥成功。
                System.out.println("Gen ECC KeyPair  ok！");
              }
              System.out.println("pubEncode="+new String(Base64.encode(kr.getPublic().getEncoded())));

              //定义签名对象
              //参数说明：
              //algorithm：签名的算法，一般格式：“SM3/SM2”
              //provider：JCE提供者的名字，一般应为：“ZAYKProvider”
              Signature tSig = Signature.getInstance("SM3/SM2", "ZAYKProvider");	  // ??----------
              
              //SignedObject(object,privatekey,signingEngine)
              //定义SignedObject类的对象，对一个Object进行签名。
              //参数说明：
              //object：需要进行签名的对象。
              //privatekey：用来进行签名的私钥。
              //signingEngin：用来进行签名的引擎，应该为上面定义的Signature类的对象。
              tSig.initSign(kr.getPrivate());

              //update(content)
              //更新签名数据
              //参数说明：
              //content：需要签名的数据test obj
              tSig.update("test obj test obj".getBytes());

              //sign()
              //对数据进行签名
              //返回值：签名后的结果。
              byte[] signed = tSig.sign();
              
              if(signed ==null)
              {
            	  System.out.println("SM2 Sign Err");
            	  return ;
              }
              Signature sSig = Signature.getInstance("SM3/SM2", "ZAYKProvider");
              sSig.initVerify(kr.getPublic());
              //update(content)
              //更新签名数据
              //参数说明：
              //content：需要验证签名的数据
              sSig.update("test obj test obj".getBytes());

              //verify(signedData);
              //对签名进行验证
              //参数说明：
              //signedData：签名后的数据
              //返回值
              //true   验证成功
              //false  验证失败
             // boolean tb=sSig.verify(Base64.decode("MEYCIQDNz+8ER98UaTsQ/tP3gLfQpJGJvPfMONUUHqgxj6HGJgIhABerRY7z6XeCF5ogg0Hn7T9uGZ0AKaYXcMZPwLs2A8wo".getBytes()));
             // System.out.println("signed="+signed.length);
              boolean tb=sSig.verify(signed);
              if (tb == true)
              {
                //验证成功。
                System.out.println("verify ok");
              }
              else
              {
            	  System.out.println("verify ERR");
              }

            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
            }
            
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    public static void SM3() {
    	try{
        	MessageDigest md=MessageDigest.getInstance("SM3","ZAYKProvider");
        	md.update("fadsfqwefawefasdf".getBytes());
        	byte[] hashData=md.digest();
        	System.out.println(new String(Base64.encode(hashData)));
    	}catch(Exception e)
    	{
    		System.out.println("SM3 Hash Err"+e.getMessage());
    	}

    }
    public static void Random(){
    	try{
    		SecureRandom sr = SecureRandom.getInstance("RealRND","ZAYKProvider");
    		byte[] randomData=new byte[128];
    		for(int i=0;i<randomData.length;i++)
    			randomData[i]=0x00;
    		
    		sr.nextBytes(randomData);
        	System.out.println(new String(Base64.encode(randomData)));
    	}catch(Exception e)
    	{
    		System.out.println("Random Err"+e.getMessage());
    	}

    }
    
   

    public static void TestRSAKeyGenFunc() {
        int keynum = -1;
        int keylength = -1;
        while( keynum<0)
            keynum = getInput("Please Input the KeyNumber or key mod:", 3);
        if(keynum==0)
        	keynum=1024;
        try
        {
            KeyPairGenerator pg = KeyPairGenerator.getInstance("RSA","ZAYKProvider");

            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
              }
              else
              {
                //生成密钥成功。
            	  System.out.println("RSA PubK = " + Base64.encode(kr.getPublic().getEncoded()));
                System.out.println("ok！");
              }
            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    public static void TestRSAEncDecFunc() {
        int keynum = -1;
        int keylength = -1;
        while( keynum<0)
            keynum = getInput("Please Input the KeyNumber or key mod:", 3);
        
        plain="fdsadjfioawejgasdfkasp32ir90ksadlfkawop".getBytes();
        try
        {
            KeyPairGenerator pg = KeyPairGenerator.getInstance("RSA","ZAYKProvider");
            //初始化密钥对生成器
            //参数说明：
            //keynum：1024、2048：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
                System.out.println("Gen RSA KeyPair Error!");
                return;
              }
              else
              {
                //生成密钥成功。
                System.out.println("ok！");
              }
            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
              return;
            }
            
            try
            {

                
                Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                                "ZAYKProvider");

                 System.out.println("Provider:"+encCipher.getProvider());
                        
                //init(mode,key)
                //初始化Cipher类的对象
                //参数说明：
                //mode：对象的操作模式，一般为Cipher.ENCRYPT_MODE或者Cipher.DECRYPT_MODE等
                //key：用于对称加密的对称密钥
                encCipher.init(Cipher.ENCRYPT_MODE, kr.getPrivate());
                //doFinal(content)
                //通过调用对content中的内容进行加密。
                //返回值：加密后的结果。
                byte[] tTemp = encCipher.doFinal(plain);
                if (tTemp == null)
                {
                    System.out.println("RSA PKCS1Padding Mode Encrypt ERROR! Return value is NULL!");
                }else
                {
                    //定义解密Cipher类对象
                    
                    
                    System.out.println("RSA PKCS1Padding Mode Encrypt OK tTempLen:"+tTemp.length);
                    //Cipher decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "ZAYKProvider");
                   
                    Cipher decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "ZAYKProvider");
                     
                    //初始化Cipher类对象
                    decCipher.init(Cipher.DECRYPT_MODE, kr.getPublic());
                    //调用解密函数
                   // byte[] tResult1 = decCipher.update(tTemp1);
                    byte[] tResult = decCipher.doFinal(tTemp);
                    
                    if (tResult == null)
                    {
                        System.out.println("RSA PKCS1Padding Mode Decrypt ERROR! Return value is NULL!");
                    }      
                    //比较结果  
                    if (Arrays.areEqual(plain,tResult))
                        System.out.println("RSA PKCS1Padding Mode Encrypt and Decrypt Success!");
                      else
                        System.out.println("RSA PKCS1Padding Mode Encrypt and Decrypt ERROR!");
                }
 
            }
            catch(Exception e)
            {
                System.out.println("RSA PKCS1Padding Mode Encrypt and Decrypt ERROR!");
                e.printStackTrace();
            }

            try
            {  
            	if(keynum==1024)
            	{
                	plain=new byte[128];
            	}
            	else{
            		plain=new byte[256];
            	}

            	for(int i=0;i<plain.length;i++)
            		plain[i]=(byte)1;
                //定义加密Cipher类对象
                Cipher encCipher = Cipher.getInstance("RSA/ECB/NoPadding", "ZAYKProvider");
                //初始化Cipher对象
                encCipher.init(Cipher.ENCRYPT_MODE, kr.getPublic());
                //调用加密函数
                byte[] tTemp = encCipher.doFinal(plain);
                if (tTemp == null)
                {
                    System.out.println("RSA NoPadding Mode Encrypt ERROR! Return value is NULL!");
                }else
                {
                    //定义解密Cipher类对象
                    Cipher decCipher = Cipher.getInstance("RSA/ECB/NoPadding", "ZAYKProvider");
                    //初始化Cipher对象
                    decCipher.init(Cipher.DECRYPT_MODE, kr.getPrivate());
                    //调用解密函数
                    byte[] tResult = decCipher.doFinal(tTemp);
                    
                    if (tResult == null)
                    {
                        System.out.println("RSA NoPadding Mode Decrypt ERROR! Return value is NULL!");
                    }       
                    //比较结果             
                    if (Arrays.areEqual(plain,tResult))
                        System.out.println("RSA NoPadding Mode Encrypt and Decrypt Success!");
                      else
                        System.out.println("RSA NoPadding Mode Encrypt and Decrypt ERROR!");
                }
            }
            catch(Exception e)
            {
                System.out.println("RSA NoPadding Mode Encrypt and Decrypt ERROR!");
                e.printStackTrace();
            }        }
        catch(Exception e)
        {
            System.out.println("RSA Encrypt and Decrypt ERROR!");
            e.printStackTrace();
        }
    }

    public static void TestRSASignVerFunc() {
        int keynum = -1;
        int keylength = -1;
        while( keynum<0)
            keynum = getInput("Please Input the KeyNumber or key mod:", 3);
        
        try
        {
            KeyPairGenerator pg = KeyPairGenerator.getInstance("RSA","ZAYKProvider");

            //初始化密钥对生成器
            //参数说明：
            //keynum：1024、2048：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
                System.out.println("Gen RSA KeyPair Error!");
                return;
              }
              else
              {
                //生成密钥成功。
                System.out.println("ok！");
              }
              
              Signature tSig = Signature.getInstance("SHA1WithRSA", "ZAYKProvider");

              //参数说明：
              //privatekey：用来进行签名的私钥。
              tSig.initSign(kr.getPrivate());
              
              tSig.update("11111111".getBytes());
              //sign()
              //对数据进行签名
              //返回值：签名后的结果。
              byte[] signed = tSig.sign();
              System.out.println("RSA Sign="+new String(Base64.encode(signed)));
         
              //从数组中获得相应的密钥对，通过getPublic()函数获得密钥对中的公钥，用于验证签名操作。
              PublicKey pubKey = kr.getPublic();

              //定义Signature类的对象，用于指明SignedObject类的对象被签名时的算法及提供者名称。参数含义同上。
              Signature sSig = Signature.getInstance("SHA1WithRSA","ZAYKProvider");
              //verify(publicKey)
              //调用SignedObject类中的verify()函数对签名进行验证。
              //参数说明：
              //publicKey：用于验证签名的公钥。
              sSig.initVerify(kr.getPublic());
              System.out.println(new String(Base64.encode(kr.getPublic().getEncoded())));
              
              //返回值：
              sSig.update("11111111".getBytes());

              //verify(signedData);
              //对签名进行验证
              //参数说明：
              //signedData：签名后的数据
              //返回值
              //true   验证成功
              //false  验证失败
             // boolean tb=sSig.verify(Base64.decode("CTI6XV5BW6HG8HtoQDS8CgMXK1+4leSTN1u9HPP85Ke8BnT19RTcb6vBDyzebobWv7D/HRBCwEDEGRfBzhW/ZMz5ikHm/MBfPm6dbZH9AUcRFI9AZbXwKL9JNeKEd+wOR2AMUQjbzvrArGicEEKpB7EK6sUB15HYYm9hzS145rXm62GGroB0l53ETGLZD4MxetiEcfTCKlSpx4yHchpHqiIBQ1Qn5SukHL8lBKzSkN93Ce6TfeoWsimzMEnautrvE3pkuiAxsuR1DqyqA/xU42mPJlnffCRQW2Oj+VeryPN2KiqwYmZgmacgKqY5E8+qgouT+LK6TyutnBWQ6dg4rw==".getBytes()));   
              boolean tb=sSig.verify(signed);
              if (tb == true)
                  System.out.println("ok！");
              else
              {
                  System.out.println("fail！");
              }

            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    @SuppressWarnings("unused")
	public static void TestRSAWrapUnwrapFunc() {
        int keynum = -1;
        int keylength = -1;
        while( keynum<0)
            keynum = getInput("Please Input the KeyNumber or key mod:", 3);

        try
        {
        	 //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
            KeyPairGenerator pg = KeyPairGenerator.getInstance("RSA","ZAYKProvider");
            //初始化密钥对生成器
            //参数说明：
            //keynum：1024、2048：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
                System.out.println("Gen RSA KeyPair Error!");
                return;
              }
              else
              {
                //生成密钥成功。
                System.out.println("ok！");
              }
            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
              return;
            }
            
            System.out.print("Wrap&UnWrap Using Key Name: " + keynum + " ... ");

            //从数组中获得相应的密钥对，通过getPublic()函数获得密钥对中的公钥，用于密钥封装操作。
            PublicKey pubKey = kr.getPublic();

            //定义Cipher类的对象，用于对密钥进行封装。参数含义同上。
            Cipher cp = Cipher.getInstance(pubKey.getAlgorithm(), "ZAYKProvider");

            //定义随机数对象，用于初始化Cipher类的对象，参数含义同上。
            SecureRandom wasr = SecureRandom.getInstance("RealRND","ZAYKProvider");

            //初始化Cipher类的对象。通过Cipher.WRAP_MODE指定为密钥封装模式，其他参数同上。
            cp.init(Cipher.WRAP_MODE, pubKey, wasr);

            //定义随机数对象，用于生成对称密钥。参数含义同上。
            SecureRandom sr = SecureRandom.getInstance("RealRND","ZAYKProvider");


            SecretKey key = new SecretKeySpec("bbbbbbbbcccccccc".getBytes(), "SM4");
            if (key == null)
            {
                System.out.println("fail！");
                System.out.println("Gen SecretKey Error!");
                return;
            }
            
            //定义Cipher类的对象，用于对称算法加密。参数含义同上。
            Cipher cie = Cipher.getInstance("SM4/ECB/PKCS5Padding", "ZAYKProvider");

            cie.init(Cipher.ENCRYPT_MODE, key, sr);

            //对数据进行对称加密操作。参数含义同上。
            byte[] conts = cie.doFinal("zayk".getBytes());

            //wrap(key)
            //对对称算法的密钥进行封装。
            //参数说明：
            //key：需要被封装的对称密钥。
            //返回值：封装后的对称密钥。
            byte[] keyCont = cp.wrap(key);
            if (keyCont == null)
            {
                System.out.println("fail！");
                System.out.println("Wrap SecretKey Error!");
                return;
            }

            //从数组中获得相应的密钥对，通过getPrivate()函数获得密钥对中的私钥，用于密钥解封操作。
            PrivateKey PriKey = kr.getPrivate();

            //定义Cipher类的对象，用于对密钥进行解封。参数含义同上。
            Cipher cp1 = Cipher.getInstance(PriKey.getAlgorithm(), "ZAYKProvider");

            //初始化Cipher类的对象，通过参数Cipher.UNWRAP_MODE设置模式为对密钥进行解封。参数含义同上。
            cp1.init(Cipher.UNWRAP_MODE, PriKey, wasr);

            //unwrap(key,algorithm,type)
            //解封对称加密密钥
            //参数说明：
            //key：等待解封的密钥
            //algorithm：等待解封的密钥对应的对称加密算法
            //type：等待解封的密钥的类型，一般应为：Cipher.SECRET_KEY
            //返回值：解封后的对称加密密钥。
            Key unkey = cp1.unwrap(keyCont, "SM4", Cipher.SECRET_KEY);
            if (unkey == null)
            {
                System.out.println("fail！");
                System.out.println("UnWrap SecretKey Error!");
                return;
            }

            //定义Cipher类的对象，用于对称算法解密。参数含义同上。
            Cipher cid = Cipher.getInstance("SM4/ECB/PKCS5Padding", "ZAYKProvider");

            //初始化Cipher类的对象，用于对称算法解密。其中的解密密钥通过上面的解封操作得到。参数含义同上。
            cid.init(Cipher.DECRYPT_MODE, unkey, sr);

            //对称加密算法解密正文。参数含义同上。
            byte[] dec = cid.doFinal(conts);
            if (dec == null)
            {
                System.out.println("fail！");
                System.out.println("UnWraped SM4 Key Decrypt Error!");
                return;
            }
            String decStr = new String(dec);
            if (decStr.equals("zayk"))
              //测试成功。
              System.out.println("OK ！");
            else {
              //测试失败。
              System.out.println("Fail ！");
            }

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    
         
    public static void TestSMEncDecFunc() {
   	    SecretKey key2 = null; //对称密钥值
        AlgorithmParameterSpec params = null; //运算IV值
   	 
       String[] enProc = { "SM1/ECB/PKCS5NOPadding","SM1/CBC/PKCS5NOPadding","SM4/ECB/PKCS5NOPadding","SM4/CBC/PKCS5NOPadding","SM1/ECB/PKCS5Padding","SM1/CBC/PKCS5Padding","SM4/ECB/PKCS5Padding","SM4/CBC/PKCS5Padding",
    		   "AES/ECB/PKCS5NOPadding","AES/CBC/PKCS5NOPadding","AES/ECB/PKCS5Padding","AES/CBC/PKCS5Padding"//,
    		   //"DES/ECB/PKCS5NOPadding","DES/CBC/PKCS5NOPadding","DES/ECB/PKCS5Padding","DES/CBC/PKCS5Padding"
    		   };

        int j,error = 0;
        System.out.println("SM1加密，解密测试.");
        try {

            for (j = 0; j < enProc.length; j++) {
            	
                if(j<12)
                {
                	//设置对称运算密钥

                   // key2 = new SecretKeySpec("bbbbbbbbcccccccc".getBytes(), "SM4");
                    
                  //设置对称运算IV值
                  //  params = new IvParameterSpec("1111222211112222".getBytes());
                	KeyGenerator kg=KeyGenerator.getInstance("SM4","ZAYKProvider");
                	kg.init(128);
                	key2=kg.generateKey();
                }
                else
                {
                	//设置对称运算密钥
                    key2 = new SecretKeySpec("bbbbbbbb".getBytes(), "DES");

                  //设置对称运算IV值
                    params = new IvParameterSpec("11112222".getBytes());

                }
                
            Cipher cie = Cipher.getInstance(enProc[j], "ZAYKProvider");

            //init(mode,key,random)
            //初始化Cipher类的对象
            //参数说明：
            //mode：对象的操作模式，一般为Cipher.ENCRYPT_MODE或者Cipher.DECRYPT_MODE等
            //key：用于对称加密的对称密钥
            //params：用于反馈模式加密的初始化矩阵IV
            //random：用于加密的随机数。
            cie.init(Cipher.ENCRYPT_MODE, key2, params,new SecureRandom());

            //doFinal(content)
            //通过调用对content中的内容进行加密。
            //返回值：加密后的结果。
            byte[] conts = cie.doFinal("1234567812345678".getBytes());
            if (conts == null)
            {
                System.out.println("conts = null fail！");
                System.out.println("SM1 Encrypt Error!");
                continue;
            }  
            
            System.out.println(enProc[j] + "   " + new String(Base64.encode(conts)));
            //定义Cipher类的对象，用于解密。参数含义同上。
            Cipher cid = Cipher.getInstance(enProc[j], "ZAYKProvider");

            cid.init(Cipher.DECRYPT_MODE, key2, params,  new SecureRandom());

            //调用doFinal()解密正文
            //返回值：解密后的结果。
            byte[] dec = cid.doFinal(conts);
            if (dec == null)
            {
                System.out.println("dec = null fail！");
                System.out.println("SM1 Decrypt Error!");
                continue;
            }  
            String decStr = new String(dec);
            if (decStr.equals("1234567812345678"))
              //测试成功
              System.out.println("ok！");
            else {
              //测试失败
              error = 1;
              System.out.println("compare fail！");
            }
          }
        }
        catch (Exception es) {
          //测试失败
          error = 1;
          System.out.println("Exception fail！");
          es.printStackTrace();
        }
        if (error == 0)
          System.out.println("测试成功！");
        else
          System.out.println("--->测试失败！！！");
    }
    
    public static void TestSM2WrapUnwrapFunc() {
        int keynum = -1;
        int keylength = -1;
        while( (keynum<0) || (keynum>99) )
            keynum = getInput("Please Input the KeyNumber (0--99) :", 3);

        try
        {                                                                                          

             //KeyPairGenerator.getInstance(algorithm,provider)
            //参数说明：
            //algorithm：设置密钥对类型，一般应为“ECC”。
            //provider：JCE提供者的名字，一般应为：“DatechCrypto”
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2","ZAYKProvider");

            //initialize(keysize,random)
            //初始化密钥对生成器
            //参数说明：
            //keynum：指定生成密钥的长度，一般为1024或者2048
            //random：指定用来生成密钥的随机数，应为上一步获得的随机数对象。
            pg.initialize(keynum, new SecureRandom());
            KeyPair kr = null;
            try {

              //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
              kr = pg.genKeyPair();
              if (kr == null)
              {
                System.out.println("fail！");
                System.out.println("Gen SM2 KeyPair Error!");
                return;
              }
              else
              {
                //生成密钥成功。
                System.out.println("ok！");
              }
            }
            catch (Exception eeee) {
              //生成失败。
              System.out.println("fail！");
              eeee.printStackTrace();
              return;
            }
            

            PublicKey pubKey = kr.getPublic();

            //定义Cipher类的对象，用于对密钥进行封装。参数含义同上。
            Cipher cp = Cipher.getInstance(pubKey.getAlgorithm(), "ZAYKProvider");

            //初始化Cipher类的对象。通过Cipher.WRAP_MODE指定为密钥封装模式，其他参数同上。
            cp.init(Cipher.WRAP_MODE, pubKey, new SecureRandom());

            
            SecretKey key = new SecretKeySpec("bbbbbbbbcccccccc".getBytes(), "SM4");
            if (key == null)
            {
                System.out.println("fail！");
                System.out.println("Gen SecretKey Error!");
                return;
            }
            
            //定义Cipher类的对象，用于对称算法加密。参数含义同上。
            Cipher cie = Cipher.getInstance("SM4/ECB/PKCS5Padding", "ZAYKProvider");
            
            cie.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());

            //对数据进行对称加密操作。参数含义同上。
            byte[] conts = cie.doFinal("zayk".getBytes());


            //wrap(key)
            //对对称算法的密钥进行封装。
            //参数说明：
            //key：需要被封装的对称密钥。
            //返回值：封装后的对称密钥。
            byte[] keyCont = cp.wrap(key);
            if (keyCont == null)
            {
                System.out.println("Fail ！");
                System.out.println("Wrap SecretKey Error!");
                return;
            }

            //从数组中获得相应的密钥对，通过getPrivate()函数获得密钥对中的私钥，用于密钥解封操作。
            PrivateKey PriKey = kr.getPrivate();

            //定义Cipher类的对象，用于对密钥进行解封。参数含义同上。
            Cipher cp1 = Cipher.getInstance(PriKey.getAlgorithm(), "ZAYKProvider");

            //初始化Cipher类的对象，通过参数Cipher.UNWRAP_MODE设置模式为对密钥进行解封。参数含义同上。
            cp1.init(Cipher.UNWRAP_MODE, PriKey,  new SecureRandom());

            //unwrap(key,algorithm,type)
            //解封对称加密密钥
            //参数说明：
            //key：等待解封的密钥
            //algorithm：等待解封的密钥对应的对称加密算法
            //type：等待解封的密钥的类型，一般应为：Cipher.SECRET_KEY
            //返回值：解封后的对称加密密钥。
            Key unkey = cp1.unwrap(keyCont, "SM4", Cipher.SECRET_KEY);
            if (unkey == null)
            {
                System.out.println("Fail ！");
                System.out.println("UnWrap SecretKey Error!");
                return;
            }

            //定义Cipher类的对象，用于对称算法解密。参数含义同上。
            Cipher cid = Cipher.getInstance("SM4/ECB/PKCS5Padding", "ZAYKProvider");

            //初始化Cipher类的对象，用于对称算法解密。其中的解密密钥通过上面的解封操作得到。参数含义同上。
            cid.init(Cipher.DECRYPT_MODE, unkey, new SecureRandom());

            //对称加密算法解密正文。参数含义同上。
            byte[] dec = cid.doFinal(conts);
            if (dec == null)
            {
                System.out.println("Fail ！");
                System.out.println("UnWraped SM4 Key Decrypt Error!");
                return;
            }
            String decStr = new String(dec);
            if (decStr.equals("zayk"))
              //测试成功。
              System.out.println("OK ！");
            else {
              //测试失败。
              System.out.println("Fail ！");
            }

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
