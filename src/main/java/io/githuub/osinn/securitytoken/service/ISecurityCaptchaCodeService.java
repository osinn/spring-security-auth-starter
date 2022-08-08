package io.githuub.osinn.securitytoken.service;

import io.githuub.osinn.securitytoken.security.dto.CaptchaCodeDTO;

/**
 * 图形验证码接口
 *
 * @author wency_cai
 */
public interface ISecurityCaptchaCodeService {

    /**
     * 创建图形验证码
     *
     * @return 返回base64 图形验证码对象
     */
    CaptchaCodeDTO createCaptchaCode();

    /**
     * 返回图形验证码值，用于比较用户输入的图形验证码
     *
     * @param codeKey 图形验证码唯一key
     * @return 返回图形验证码值
     */
    String getCaptchaCode(String codeKey);

    /**
     * 删除图形验证码
     *
     * @param codeKey
     */
    void delete(String codeKey);
}
