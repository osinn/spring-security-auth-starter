package io.github.osinn.securitytoken.utils;

import cn.hutool.json.JSONConfig;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.osinn.securitytoken.security.dto.CustomizeResponseBodyField;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * @author wency_cai
 **/
public class ResponseUtils {

    public static CustomizeResponseBodyField customizeResponseBodyField;

    public static void outWriter(int statusCode, String message, String errorMessage, HttpServletRequest request, HttpServletResponse response) throws IOException {
        JSONObject jsonObject = JSONUtil.createObj(JSONConfig.create().setIgnoreNullValue(false));
        jsonObject.set(customizeResponseBodyField.getMessageField(), message);
        jsonObject.set(customizeResponseBodyField.getErrorField(), errorMessage);
        jsonObject.set(customizeResponseBodyField.getCodeField(), statusCode);
        jsonObject.set("path", request.getRequestURI());
        jsonObject.set("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(JSONUtil.toJsonStr(jsonObject));
    }
}
