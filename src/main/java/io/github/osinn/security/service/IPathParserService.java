package io.github.osinn.security.service;

/**
 * 路径匹配
 *
 * @author wency_cai
 */
public interface IPathParserService {

    /**
     * 检查匹配
     *
     * @param uriTemplate 路径模板
     * @param path        请求路径
     * @return boolean
     */
    boolean checkMatches(String uriTemplate, String path);
}
