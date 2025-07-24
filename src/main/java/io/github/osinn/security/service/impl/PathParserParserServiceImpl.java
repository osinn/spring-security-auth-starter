package io.github.osinn.security.service.impl;

import io.github.osinn.security.service.IPathParserService;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * 描述 AntPathMatcher
 *
 * @author wency_cai
 */
public class PathParserParserServiceImpl implements IPathParserService {

    private final PathPatternParser pathPatternParser = new PathPatternParser();

    @Override
    public boolean checkMatches(String uriTemplate, String requestUri) {
        return pathPatternParser.parse(uriTemplate).matches(PathContainer.parsePath(requestUri));
    }

}
