package io.githuub.osinn.securitytoken.enums;


import org.springframework.lang.Nullable;

/**
 * @author wency_cai
 * @description: 描述
 **/
public enum JwtHttpStatus {

    /**
     * 验证码错误
     */
    TOKEN_UNAUTHORIZED(4001, "用户名或密码错误"),
    CODE_UNAUTHORIZED(4002, "验证码错误"),
    SC_FORBIDDEN(4003, "权限不足"),

    NOT_FOUND(4004,"找不到资源"),

    PASSWORD_ERROR(4005, "密码解密错误"),
    /**
     * 验证码过期或不存在
     */
    NOT_FOUND_CODE(4006, "验证码过期"),

    TOKEN_EXPIRE(4007, "登录超时,请重新登录"),

    NOT_FOUND_ACCOUNT(4008, "账户不存在"),

    DISABLED_ACCOUNT(4009, "账户已被禁用"),

    LOCK_ACCOUNT(4010, "账户已被锁定"),

    LOGOUT_FAIL(4011, "退出登录失败"),

    LOGOUT_SUCCESS(20000, "退出登录成功"),

    INTERNAL_SERVER_ERROR(5000,"服务异常");

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
