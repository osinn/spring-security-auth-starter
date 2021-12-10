package com.gitee.osinn.boot.securityjwt.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JsonMapper {

    private static ObjectMapper objectMapper;

    private static JsonMapper jsonMapper = new JsonMapper();

    private JsonMapper() {
        objectMapper = new ObjectMapper();
        // 转换为格式化的json
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.SnakeCaseStrategy.SNAKE_CASE);
        // 如果json中有新增的字段并且是实体类类中不存在的，不报错
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS,false);
    }

    public static JsonMapper getInstance() {
        return jsonMapper;
    }

    public static <T> String toJson(T t) {
        String result = null;
        try {
            result = objectMapper.writeValueAsString(t);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static <T> T fromJson(Object value, Class<T> t) {
        T result = null;
        try {
            result = objectMapper.readValue(objectMapper.writeValueAsBytes(value), t);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }


    public static <T> List<T> fromJson(Object value, Class cls, Class<T> t) {
        List<T> result = null;
        try {
            JavaType type = objectMapper.getTypeFactory().constructCollectionType(cls, t);
            result = objectMapper.readValue(objectMapper.writeValueAsBytes(value), type);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static <K, V> Map<K, V> fromJson(Object object, Class cls, Class<K> key, Class<V> value) {
        Map<K, V> result = null;
        try {
            JavaType type = objectMapper.getTypeFactory().constructMapLikeType(cls, key, value);
            result = objectMapper.readValue(objectMapper.writeValueAsBytes(object), type);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }
}