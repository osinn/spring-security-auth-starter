package io.github.osinn.security.service.impl;

import io.github.osinn.security.service.IPathParserService;
import org.springframework.util.AntPathMatcher;

/**
 * 描述
 *
 * @author wency_cai
 */
public class AntPathMatcherServiceImpl implements IPathParserService {

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public boolean checkMatches(String uriTemplate, String requestUri) {
        return antPathMatcher.match(uriTemplate, requestUri);
    }
}
