package io.github.osinn.security.service.impl;

import cn.hutool.core.lang.Snowflake;
import cn.hutool.core.util.IdUtil;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.security.dto.CaptchaCodeDTO;
import io.github.osinn.security.service.ISecurityCaptchaCodeService;
import io.github.osinn.security.utils.RedisUtils;
import com.wf.captcha.SpecCaptcha;
import jakarta.annotation.Resource;

/**
 * 图形验证码服务
 *
 * @author wency_cai
 */
public class SecurityCaptchaCodeServiceImpl implements ISecurityCaptchaCodeService {

    @Resource
    private RedisUtils redisUtils;

    @Resource
    private SecurityProperties securityService;

    /**
     * 创建图形验证码
     *
     * @return
     */
    @Override
    public CaptchaCodeDTO createCaptchaCode() {
        Snowflake snowflake = IdUtil.getSnowflake(1, 1);
        long id = snowflake.nextId();

        SpecCaptcha specCaptcha = new SpecCaptcha(111, 36, 4);
        String verCode = specCaptcha.text().toLowerCase();
        String key = String.valueOf(id);
        SecurityProperties.CaptchaCode captchaCode = securityService.getCaptchaCode();
        redisUtils.set(captchaCode.getCodeKey().concat(key), verCode, captchaCode.getCaptchaExpiration());

        return new CaptchaCodeDTO(key, specCaptcha.toBase64());
    }

    /**
     * 返回图形验证码
     *
     * @param codeKey 图形验证码唯一key
     * @return
     */
    @Override
    public String getCaptchaCode(String codeKey) {
        SecurityProperties.CaptchaCode captchaCode = securityService.getCaptchaCode();
        // 从redis取出验证码
        String code = redisUtils.get(captchaCode.getCodeKey().concat(codeKey), String.class);
        return code;
    }

    /**
     * 中redis缓存中删除图形验证码
     *
     * @param codeKey
     */
    @Override
    public void delete(String codeKey) {
        SecurityProperties.CaptchaCode captchaCode = securityService.getCaptchaCode();
        redisUtils.del(captchaCode.getCodeKey().concat(codeKey));
    }
}
