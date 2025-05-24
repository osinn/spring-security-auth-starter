package io.github.osinn.security.utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.List;

/**
 * Gson工具类
 *
 * @author wency_cai
 */
public class GsonMapper {

    public static final Gson GSON = new Gson();

    public static <T> T toBean(String str, Class<T> clazz) {
        if (str == null || "".equals(str)) {
            return null;
        }
        T bean = GSON.fromJson(str, clazz);
        return bean;
    }

    public static <T> List<T> toListBean(String json, Class<T> clazz) {
        Type type = TypeToken.getParameterized(List.class, clazz).getType();
        return new Gson().fromJson(json, type);
    }


    public static String toJsonStr(Object obj) {
        if (obj == null || "".equals(obj)) {
            return null;
        }
        String json = GSON.toJson(obj);
        return json;
    }

}
