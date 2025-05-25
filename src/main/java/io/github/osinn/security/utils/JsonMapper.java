package io.github.osinn.security.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * JSON工具类
 *
 * @author wency_cai
 */
public class JsonMapper {

    private static final ObjectMapper objectMapper = new ObjectMapper();


    public static <T> String toJsonStr(T obj) {
        if (obj == null || "".equals(obj)) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("序列化失败", e);
        }
    }

    // 获取对象
    public static <T> T toBean(String json, Class<T> clazz) {
        try {
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("反序列化失败", e);
        }
    }
}
