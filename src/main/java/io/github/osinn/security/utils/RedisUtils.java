package io.github.osinn.security.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.*;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * @author wency_cai
 **/
@Slf4j
public class RedisUtils {

    private static RedisTemplate<String, Object> redisTemplate;

    public static void initAfterPropertiesSet(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(factory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.afterPropertiesSet();
        RedisUtils.redisTemplate = redisTemplate;
    }

    /**
     * 指定缓存失效时间
     *
     * @param key  键
     * @param time 时间(秒)
     */
    public static boolean expire(String key, long time) {
        try {
            if (time > 0) {
                redisTemplate.expire(key, time, TimeUnit.SECONDS);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return false;
        }
        return true;
    }

    /**
     * 根据 key 获取过期时间
     *
     * @param key 键 不能为null
     * @return 时间(秒) 返回0代表为永久有效, 返回-2代表不存在
     */
    public static long getExpire(String key) {
        return redisTemplate.getExpire(key);
    }

    /**
     * 查找匹配key
     *
     * @param pattern key
     * @return /
     */
    public static List<String> scan(String pattern) {
        Iterable<String> keysByPattern = redisTemplate.keys(pattern);
        List<String> keys = new ArrayList<>();
        for (String key : keysByPattern) {
            keys.add(key);
        }
        return keys;
    }

    /**
     * 删除缓存
     *
     * @param key 可以传一个值 或多个
     */
    public static void del(String... key) {
        if (key != null && key.length > 0) {
            if (key.length == 1) {
                redisTemplate.delete(key[0]);
            } else {
                redisTemplate.delete(Arrays.asList(key));
            }
        }
    }

    // ============================String=============================

    /**
     * 普通缓存获取
     *
     * @param key 键
     * @return 值
     */
    public static <T> T get(String key) {
        return (T) redisTemplate.opsForValue().get(key);
    }

    /**
     * 普通缓存获取
     *
     * @param key 键
     * @return 值
     */
    public static <T> List<T> getList(String key) {
        return (List<T>) redisTemplate.opsForValue().get(key);
    }

    /**
     * 普通缓存放入
     *
     * @param key   键
     * @param value 值
     * @return true成功 false失败
     */
    public static boolean set(String key, Object value) {
        redisTemplate.opsForValue().set(key, value);
        return true;
    }

    /**
     * 普通缓存放入并设置时间
     *
     * @param key   键
     * @param value 值
     * @param time  时间(秒) time要大于0 如果time小于等于0 将设置无限期
     * @return true成功 false 失败
     */
    public static boolean set(String key, Object value, long time) {
        if (time <= 0) {
            redisTemplate.opsForValue().set(key, value, time);
        } else {
            redisTemplate.opsForValue().set(key, value, time, TimeUnit.SECONDS);
        }
        return true;
    }

    /**
     * 根据前缀删除缓存
     *
     * @param prefix 前缀
     */
    public static void deleteCacheByPrefix(String prefix) {
        List<String> list = scan(prefix + "*");
        if (!list.isEmpty()) {
            redisTemplate.delete(list);
        }
    }

    /**
     * 根据前缀获取缓存
     *
     * @param prefix 前缀
     */
    public static <T> List<T> fetchLike(String prefix) {
        List<String> keys = scan(prefix);
        List<T> list = new ArrayList<>();
        for (String key : keys) {
            Object object = redisTemplate.opsForValue().get(key);
            if (object != null) {
                list.add((T) object);
            }
        }
        list.removeIf(Objects::isNull);
        return list;
    }
}
