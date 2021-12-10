package com.gitee.osinn.boot.securityjwt.security.dto;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

/**
 * 登录请求信息
 */
@Getter
@Setter
public class AuthUser {

    /**
     * 登录用户名
     */
    @NotBlank
    private String username;

    /**
     * 登录密码
     */
    @NotBlank
    private String password;

    /**
     * 验证码
     */
    private String code;

    /**
     * 创建验证码时生成的uuid,用于校验验证时查询验证码（即为redis缓存验证码 key）
     */
    private String uuid = "";

    @Override
    public String toString() {
        return "{username=" + username  + ", password= ******}";
    }
}
