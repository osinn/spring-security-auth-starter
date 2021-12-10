package com.gitee.osinn.boot.securityjwt.utils;

import com.google.common.base.Charsets;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.DigestUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;

/**
 * Des加密
 *
 * @author wency_cai
 */
public class DesEncryptUtils {

    /**
     * 偏移变量，固定占8位字节
     */
    private static String desVector = "Passw0rd";
    private static String desPassword = "Passw0rd";

    private static Cipher cipher;

    private static IvParameterSpec iv = new IvParameterSpec(desVector.getBytes(StandardCharsets.UTF_8));

    private static DESKeySpec getDesKeySpec(String source) throws Exception {
        if (source == null || source.length() == 0) {
            return null;
        }
        cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        return new DESKeySpec(desPassword.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 对称加密
     */
    public static String desEncrypt(String source) throws Exception {
        DESKeySpec desKeySpec = getDesKeySpec(source);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return byte2hex(cipher.doFinal(source.getBytes(StandardCharsets.UTF_8))).toUpperCase();
    }

    /**
     * 对称解密
     */
    public static String desDecrypt(String source) throws Exception {
        byte[] src = hex2byte(source.getBytes());
        DESKeySpec desKeySpec = getDesKeySpec(source);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] retByte = cipher.doFinal(src);
        return new String(retByte);
    }

    private static String byte2hex(byte[] inStr) {
        String stmp;
        StringBuilder out = new StringBuilder(inStr.length * 2);
        for (byte b : inStr) {
            stmp = Integer.toHexString(b & 0xFF);
            if (stmp.length() == 1) {
                // 如果是0至F的单位字符串，则添加0
                out.append("0").append(stmp);
            } else {
                out.append(stmp);
            }
        }
        return out.toString();
    }

    private static byte[] hex2byte(byte[] b) {
        int size = 2;
        if ((b.length % size) != 0) {
            throw new IllegalArgumentException("长度不是偶数");
        }
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += size) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }

    /**
     * 密码加密
     *
     * @param password
     * @return
     */
    public static String encryptPassword(String password) {
        Hasher hasher = Hashing.sha512().newHasher();
        hasher.putString("boot.api.security.jwt" + password, Charsets.UTF_8);
        password = hasher.hash().toString().toUpperCase();
        return md5DigestAsHex(password);
    }

    public static String md5DigestAsHex(String str) {
       return DigestUtils.md5DigestAsHex(str.getBytes()).toUpperCase();
    }

    public static void setDesPassword(String password) {
        desPassword = password;
    }

    public static void main(String[] args) {
        System.out.println(md5DigestAsHex("eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ6aGFuZ3NhbiIsImF1dGgiOiJ0ZXN0IiwiZXhwIjoxNjM4NzU3NTA1fQ.WmzUjwnKIbV3-d9mmHCqAgTlZjEqSPC_JhkZwTLNu9N909AD4Dd6B02OCQd5PQVUEkkTym0UbliSeNfsqHX6fg"));
    }
}
