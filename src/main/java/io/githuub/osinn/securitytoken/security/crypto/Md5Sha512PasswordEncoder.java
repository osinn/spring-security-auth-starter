package io.githuub.osinn.securitytoken.security.crypto;

import org.springframework.security.crypto.password.PasswordEncoder;
import io.githuub.osinn.securitytoken.utils.DesEncryptUtils;

/**
 * 自定义密码比较器
 *
 * @author wency_cai
 */
public class Md5Sha512PasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence charSequence) {
        return DesEncryptUtils.encryptPassword(charSequence.toString());
    }


    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 加密转换对应数据库加密方式
        rawPassword = DesEncryptUtils.encryptPassword(rawPassword.toString());
        return encodedPassword.equals(rawPassword);
    }
}
