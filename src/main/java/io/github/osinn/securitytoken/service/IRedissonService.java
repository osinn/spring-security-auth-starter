package io.github.osinn.securitytoken.service;

import org.redisson.api.RedissonClient;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @author wency_cai
 **/
public interface IRedissonService {

    /**
     * 加锁
     *
     * @param lockKey key
     */
    void lock(String lockKey);

    /**
     * 释放锁
     *
     * @param lockKey key
     */
    void unlock(String lockKey);

    /**
     * 加锁锁,设置有效期
     *
     * @param lockKey key
     * @param timeout 有效时间，默认时间单位在实现类传入
     */
    void lock(String lockKey, int timeout);

    /**
     * 加锁，设置有效期并指定时间单位
     *
     * @param lockKey key
     * @param timeout 有效时间
     * @param unit    时间单位
     */
    void lock(String lockKey, int timeout, TimeUnit unit);

    /**
     * 尝试获取锁，获取到则持有该锁返回true,未获取到立即返回false
     *
     * @param lockKey
     * @return true-获取锁成功 false-获取锁失败
     */
    boolean tryLock(String lockKey);

    /**
     * 尝试获取锁，获取到则持有该锁leaseTime时间.
     * 若未获取到，在waitTime时间内一直尝试获取，超过waitTime还未获取到则返回false
     *
     * @param lockKey   key
     * @param waitTime  尝试获取时间
     * @param leaseTime 锁持有时间
     * @param unit      时间单位
     * @return true-获取锁成功 false-获取锁失败
     */
    boolean tryLock(String lockKey, long waitTime, long leaseTime, TimeUnit unit)
            throws InterruptedException;

    /**
     * 锁是否被任意一个线程锁持有
     *
     * @param lockKey
     * @return true-被锁 false-未被锁
     */
    boolean isLocked(String lockKey);

    //lock.isHeldByCurrentThread()的作用是查询当前线程是否保持此锁定
    boolean isHeldByCurrentThread(String lockKey);

    /**
     * 同步-保存值
     *
     * @param value
     * @param <T>
     */
    <T> void setValue(String key, T value);

    /**
     * 同步-保存值
     *
     * @param key        redis的key
     * @param value      保存值
     * @param expiration 过期时间-单位秒
     * @param <T>
     */
    <T> void setValue(String key, T value, Long expiration);

    /**
     * 获取值
     *
     * @param key
     * @param <T>
     * @return
     */
    <T> T getValue(String key);


    /**
     * 保存list值
     *
     * @param listValue
     * @param <T>
     */
    <T> boolean setList(String key, Collection<T> listValue);

    /**
     * @param key        redis的key
     * @param listValue  保存的list集合
     * @param expiration 过期时间-单位秒
     * @param <T>
     * @return
     */
    <T> boolean setList(String key, Collection<T> listValue, Long expiration);

    /**
     * 获取list值
     *
     * @param key
     * @param <T>
     * @return
     */
    <T> List<T> getList(String key);

    /**
     * 删除缓存
     *
     * @param key
     */
    void delete(String key);

    /**
     * 获取RedissonClient
     *
     * @return
     */
    RedissonClient getRedissonClient();

}