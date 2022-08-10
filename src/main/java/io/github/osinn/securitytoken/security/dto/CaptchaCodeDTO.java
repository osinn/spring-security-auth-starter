package io.github.osinn.securitytoken.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 图片验证码
 *
 * @author wency_cai
 */
@Data
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
public class CaptchaCodeDTO implements Serializable {

    /**
     * 图片验证码唯一标识
     */
    private String captchaCodeKey;

    /**
     * 图片验证码 Base64编码
     */
    private String imageBase64;
}
