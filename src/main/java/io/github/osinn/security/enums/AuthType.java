package io.github.osinn.security.enums;

/**
 * @author wency_cai
 **/
public enum AuthType {

    /**
     * 请求url认证方式
     */
    URL,

    /**
     * 请求权限编码认证方式
     */
    CODE,

    /**
     * 基于服务名称请求权限编码认证方式
     */
    SERVICE,

    /**
     * 关闭权限认证¸只认证登录，不认证权限
     */
    OFF
}
