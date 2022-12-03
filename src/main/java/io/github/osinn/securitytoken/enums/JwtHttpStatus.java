package io.github.osinn.securitytoken.enums;


import org.springframework.lang.Nullable;

/**
 * 错误代码
 *
 * @author wency_cai
 **/
public enum JwtHttpStatus {

    /**
     * 用户名或密码错误
     */
    TOKEN_UNAUTHORIZED(4001, "账号或密码错误"),
    /**
     * 验证码错误
     */
    CODE_UNAUTHORIZED(4002, "验证码错误"),
    /**
     * 访问权限不足
     */
    SC_FORBIDDEN(1003, "访问权限不足"),
    /**
     * 找不到资源
     */
    NOT_FOUND(4004, "找不到资源"),
    /**
     * 密码解密错误
     */
    PASSWORD_ERROR(4005, "密码解密错误"),
    /**
     * 验证码过期或不存在
     */
    NOT_FOUND_CODE(4006, "验证码过期"),
    /**
     * 登录超时,请重新登录
     */
    TOKEN_EXPIRE(1001, "登录超时,请重新登录"),
    /**
     * 账户不存在
     */
    NOT_FOUND_ACCOUNT(4008, "账号不存在"),
    /**
     * 账户已被禁用
     */
    DISABLED_ACCOUNT(4009, "账号已被禁用，请联系管理员"),
    /**
     * 账户已被锁定
     */
    LOCK_ACCOUNT(4010, "账号已被锁定，请联系管理员"),
    /**
     * 退出登录失败
     */
    LOGOUT_FAIL(4011, "退出登录失败"),
    /**
     * 登录失败
     */
    LOGIN_FAIL(4012, "登录失败，请联系管理员"),
    /**
     * 证书过期，请联系管理员
     */
    CREDENTIALS_EXPIRED(4013, "证书过期，请联系管理员"),
    /**
     * 环境错误，请联系管理员
     */
    ENV_TAG_ERROR(4014, "环境错误，请联系管理员"),
    /**
     * 退出登录成功
     */
    LOGOUT_SUCCESS(200, "退出登录成功"),
    /**
     * 服务器异常，请联系管理员
     */
    INTERNAL_SERVER_ERROR(5000, "服务器异常，请联系管理员");

    private final String message;

    private final int code;

    JwtHttpStatus(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getMessage() {
        return this.message;
    }

    public int getCode() {
        return this.code;
    }

    public static JwtHttpStatus valueOf(int code) {
        JwtHttpStatus status = resolve(code);
        if (status == null) {
            throw new IllegalArgumentException("No matching constant for [" + code + "]");
        }
        return status;
    }


    /**
     * Resolve the given status code to an {@code HttpStatus}, if possible.
     *
     * @param statusCode the HTTP status code (potentially non-standard)
     * @return the corresponding {@code HttpStatus}, or {@code null} if not found
     * @since 5.0
     */
    @Nullable
    public static JwtHttpStatus resolve(int statusCode) {
        for (JwtHttpStatus status : values()) {
            if (status.code == statusCode) {
                return status;
            }
        }
        return null;
    }

}
