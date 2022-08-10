package io.github.osinn.securitytoken.security.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 定义响应消息字段
 *
 * @author wency_cai
 */
@Getter
@Setter
public class CustomizeResponseBodyField {

    /**
     * 消息字段
     */
    private String messageField;

    /**
     * 异常消息字段
     */
    private String errorField;

    /**
     * 响应code字段
     */
    private String codeField;
}
