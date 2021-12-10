package com.gitee.osinn.boot.securityjwt.exception;

import com.gitee.osinn.boot.securityjwt.enums.JwtHttpStatus;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * 自定义异常
 * @author wency_cai
 */
@Getter
@NoArgsConstructor
public class SecurityJwtException extends RuntimeException {

    private Integer status = BAD_REQUEST.value();

    /**
     * 构造函数初始化异常对象
     *
     * @param message 异常信息
     */
    public SecurityJwtException(String message) {
        super(message);
    }

    /**
     * 构造函数初始化异常对象
     *
     * @param message 异常消息
     * @param cause   异常堆栈信息
     */
    public SecurityJwtException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityJwtException(HttpStatus status, String msg) {
        super(msg);
        this.status = status.value();
    }

    public SecurityJwtException(int status, String msg) {
        super(msg);
        this.status = status;
    }

    public SecurityJwtException(JwtHttpStatus jwtHttpStatus) {
        super(jwtHttpStatus.getMessage());
        this.status = jwtHttpStatus.getCode();
    }

    /**
     * 构造函数初始化异常对象
     *
     * @param message 异常消息
     * @param cause   异常堆栈信息
     */
    public SecurityJwtException(int status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }
}
