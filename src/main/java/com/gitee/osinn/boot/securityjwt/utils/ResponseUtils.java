package com.gitee.osinn.boot.securityjwt.utils;

import cn.hutool.json.JSONConfig;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
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

    public static void outWriter(int statusCode, String message, String errorMessage, HttpServletRequest request, HttpServletResponse response) throws IOException {
        JSONObject jsonObject = JSONUtil.createObj(JSONConfig.create().setIgnoreNullValue(false));
        jsonObject.set("message", message);
        jsonObject.set("error", errorMessage);
        jsonObject.set("code", statusCode);
        jsonObject.set("path", request.getRequestURI());
        jsonObject.set("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(JSONUtil.toJsonStr(jsonObject));
    }
}
