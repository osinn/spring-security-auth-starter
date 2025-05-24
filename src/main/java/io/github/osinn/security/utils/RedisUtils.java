package io.github.osinn.security.utils;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.*;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * @author wency_cai
 **/
@Slf4j
@Component
public class RedisUtils {

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 指定缓存失效时间
     *
     * @param key  键
     * @param time 时间(秒)
     */
    public boolean expire(String key, long time) {
        try {
            if (time > 0) {
                stringRedisTemplate.expire(key, time, TimeUnit.SECONDS);
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
    public long getExpire(String key) {
        return stringRedisTemplate.getExpire(key);
    }

    /**
     * 查找匹配key
     *
     * @param pattern key
     * @return /
     */
    public List<String> scan(String pattern) {
        Iterable<String> keysByPattern = stringRedisTemplate.keys(pattern);
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
    public void del(String... key) {
        if (key != null && key.length > 0) {
            if (key.length == 1) {
                stringRedisTemplate.delete(key[0]);
            } else {
                stringRedisTemplate.delete(Arrays.asList(key));
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
    public <T> T get(String key, Class<T> clazz) {
        String value = stringRedisTemplate.opsForValue().get(key);
        return GsonMapper.toBean(value, clazz);
    }

    /**
     * 普通缓存获取
     *
     * @param key 键
     * @return 值
     */
    public <T> List<T> getList(String key, Class<T> clazz) {
        String value = stringRedisTemplate.opsForValue().get(key);
        return GsonMapper.toListBean(value, clazz);
    }


    /**
     * 普通缓存放入
     *
     * @param key   键
     * @param value 值
     * @return true成功 false失败
     */
    public boolean set(String key, Object value) {
        stringRedisTemplate.opsForValue().set(key, GsonMapper.toJsonStr(value));
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
    public boolean set(String key, Object value, long time) {
        stringRedisTemplate.opsForValue().set(key, GsonMapper.toJsonStr(value), time, TimeUnit.SECONDS);
        return true;
    }

    // ===============================list=================================

    /**
     * 根据前缀删除缓存
     *
     * @param prefix 前缀
     */
    public void deleteCacheByPrefix(String prefix) {
        List<String> list = scan(prefix + "*");
        if (!list.isEmpty()) {
            stringRedisTemplate.delete(list);
        }
    }

    /**
     * 根据前缀删除缓存
     *
     * @param prefix 前缀
     */
    public List<String> fetchLike(String prefix) {
        List<String> keys = scan(prefix);
        List<String> list = new ArrayList<>();
        for (String key : keys) {
            list.add(stringRedisTemplate.opsForValue().get(key));
        }
        list.removeIf(x -> x == null);
        return list;
    }
}
