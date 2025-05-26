package io.github.osinn.security.security.crypto;

import io.github.osinn.security.utils.CryptoUtils;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 自定义密码比较器
 *
 * @author wency_cai
 */
public class Md5Sha512PasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence charSequence) {
        return CryptoUtils.md5Sha512Password(charSequence.toString());
    }


    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 加密转换对应数据库加密方式
        rawPassword = CryptoUtils.md5Sha512Password(rawPassword.toString());
        return encodedPassword.contentEquals(rawPassword);
    }

}
