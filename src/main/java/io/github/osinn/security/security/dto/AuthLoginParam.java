package io.github.osinn.security.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 登录请求信息
 *
 * @author wency_cai
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthLoginParam {

    /**
     * 登录账号 - 不能为空
     */
    private String account;

    /**
     * 登录密码 - 不能为空
     */
    private String password;

    /**
     * 验证码
     */
    private String code;

    /**
     * 创建验证码时生成的uuid,用于校验验证时查询验证码（即为redis缓存验证码 key）
     */
    private String uuid = "";

    public AuthLoginParam(String account, String password) {
        this.account = account;
        this.password = password;
    }

    @Override
    public String toString() {
        return "{account=" + account + ", password= ******}";
    }
}
