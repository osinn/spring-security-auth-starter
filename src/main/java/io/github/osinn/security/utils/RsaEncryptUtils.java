package io.github.osinn.security.utils;


import com.google.common.base.Charsets;
import lombok.Data;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author wency_cai
 */
public class RsaEncryptUtils {

    public static String ALGORITHM = "RSA";
    public static final int KEY_SIZE = 1024;


    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.decodeBase64(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes(Charsets.UTF_8)));
        return outStr;
    }

    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str);
        //base64编码的私钥
        byte[] decoded = Base64.decodeBase64(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte));
        return outStr;
    }

    @Data
    public static class RsaSecretKey {
        private String publicKey;
        private String privateKey;
    }

//    public static void main(String[] args) throws Exception {
//        //生成公钥和私钥
//        RsaSecretKey rsaSecretKey = genKeyPair();
//        //加密字符串
//        String message = "df723820";
//        System.out.println("随机生成的公钥为:" + rsaSecretKey.getPublicKey());
//        System.out.println("随机生成的私钥为:" + rsaSecretKey.getPrivateKey());
//        String messageEn = encrypt(message, rsaSecretKey.getPublicKey());
//        System.out.println(message + "\t加密后的字符串为:" + messageEn);
//        String messageDe = decrypt(messageEn, rsaSecretKey.getPrivateKey());
//        System.out.println("还原后的字符串为:" + messageDe);
//    }
}

