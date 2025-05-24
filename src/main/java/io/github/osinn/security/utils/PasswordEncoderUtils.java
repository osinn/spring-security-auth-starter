package io.github.osinn.security.utils;

import io.github.osinn.security.security.crypto.Md5Sha512PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 描述
 *
 * @author wency_cai
 */
public class PasswordEncoderUtils {

    public static PasswordEncoder getPasswordEncoder(String idForEncode) {
        Map<String, PasswordEncoder> idToPasswordEncoder = new HashMap<>(3);
        idToPasswordEncoder.put("bcrypt", new BCryptPasswordEncoder());
        idToPasswordEncoder.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        idToPasswordEncoder.put("md5sha512", new Md5Sha512PasswordEncoder());

        if (idForEncode == null) {
            throw new IllegalArgumentException("加密方式不能为空");
        }
        if (!idToPasswordEncoder.containsKey(idForEncode)) {
            throw new IllegalArgumentException("加密方式 " + idForEncode + " 不在 " + idToPasswordEncoder + "中");
        }
        return idToPasswordEncoder.get(idForEncode);
    }

}
