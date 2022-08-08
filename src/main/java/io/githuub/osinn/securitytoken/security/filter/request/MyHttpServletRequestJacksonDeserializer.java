package io.githuub.osinn.securitytoken.security.filter.request;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import io.githuub.osinn.securitytoken.utils.StrUtils;

import java.io.IOException;

import static org.springframework.web.util.HtmlUtils.htmlEscape;

/**
 * xss-结合HttpMessageConverters使用
 *
 * @author wency_cai
 */
public class MyHttpServletRequestJacksonDeserializer extends JsonDeserializer<String> {

    @Override
    public String deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        if (StrUtils.isEmpty(jsonParser.getText())) {
            return jsonParser.getText();
        }
        return htmlEscape(jsonParser.getText());
    }
}