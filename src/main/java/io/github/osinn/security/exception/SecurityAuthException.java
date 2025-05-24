package io.github.osinn.security.exception;

import io.github.osinn.security.enums.AuthHttpStatus;
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
public class SecurityAuthException extends RuntimeException {

    private Integer status = BAD_REQUEST.value();

    /**
     * 构造函数初始化异常对象
     *
     * @param message 异常信息
     */
    public SecurityAuthException(String message) {
        super(message);
    }

    /**
     * 构造函数初始化异常对象
     *
     * @param message 异常消息
     * @param cause   异常堆栈信息
     */
    public SecurityAuthException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityAuthException(HttpStatus status, String msg) {
        super(msg);
        this.status = status.value();
    }

    public SecurityAuthException(int status, String msg) {
        super(msg);
        this.status = status;
    }

    public SecurityAuthException(AuthHttpStatus authHttpStatus) {
        super(authHttpStatus.getMessage());
        this.status = authHttpStatus.getCode();
    }

    /**
     * 构造函数初始化异常对象
     *
     * @param message 异常消息
     * @param cause   异常堆栈信息
     */
    public SecurityAuthException(int status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }
}
