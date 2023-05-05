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

    public static <T> T toListBean(String str) {
        if (str == null || "".equals(str)) {
            return null;
        }
        Type type = new TypeToken<List<T>>(){}.getType();
        T bean = GSON.fromJson(str, type);
        return bean;
    }

    public static String toJsonStr(Object obj) {
        if (obj == null || "".equals(obj)) {
            return null;
        }
        String json = GSON.toJson(obj);
        return json;
    }

    public static void main(String[] args) {
        Object obj = "sdasd";
        String d= toBean((String)obj, String.class);
        System.out.println(d);
    }
}