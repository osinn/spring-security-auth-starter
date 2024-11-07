package io.github.osinn.securitytoken.service.impl;

import io.github.osinn.securitytoken.service.IRedissonService;
import org.redisson.api.RBucket;
import org.redisson.api.RList;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * redisson实现分布式锁接口
 *
 * @author wency_cai
 */
public class RedissonServiceImpl implements IRedissonService {

    private RedissonClient redissonClient;

    public RedissonServiceImpl(RedissonClient redissonClient) {
        this.redissonClient = redissonClient;
    }

    @Override
    public void lock(String lockKey) {
        RLock lock = redissonClient.getLock(lockKey);
        lock.lock();
    }

    @Override
    public void unlock(String lockKey) {
        RLock lock = redissonClient.getLock(lockKey);
        lock.unlock();
    }

    @Override
    public void lock(String lockKey, int leaseTime) {
        RLock lock = redissonClient.getLock(lockKey);
        lock.lock(leaseTime, TimeUnit.MILLISECONDS);
    }

    @Override
    public void lock(String lockKey, int timeout, TimeUnit unit) {
        RLock lock = redissonClient.getLock(lockKey);
        lock.lock(timeout, unit);
    }

    @Override
    public boolean tryLock(String lockKey) {
        RLock lock = redissonClient.getLock(lockKey);
        return lock.tryLock();
    }

    @Override
    public boolean tryLock(String lockKey, long waitTime, long leaseTime,
                           TimeUnit unit) throws InterruptedException {
        RLock lock = redissonClient.getLock(lockKey);
        return lock.tryLock(waitTime, leaseTime, unit);
    }

    @Override
    public boolean isLocked(String lockKey) {
        RLock lock = redissonClient.getLock(lockKey);
        return lock.isLocked();
    }

    @Override
    public boolean isHeldByCurrentThread(String lockKey) {
        RLock lock = redissonClient.getLock(lockKey);
        return lock.isHeldByCurrentThread();
    }

    @Override
    public <T> void setValue(String key, T value) {
        RBucket<T> bucket = redissonClient.getBucket(key);
        bucket.set(value);
    }

    @Override
    public <T> void setValue(String key, T value, Long expiration) {
        if (expiration == null || expiration <= 0) {
            setValue(key, value);
        } else {
            RBucket<T> bucket = redissonClient.getBucket(key);
            bucket.set(value, expiration, TimeUnit.SECONDS);
        }
    }

    @Override
    public <T> T getValue(String key) {
        RBucket<T> bucket = redissonClient.getBucket(key);
        return bucket.get();
    }

    @Override
    public <T> boolean setList(String key, Collection<T> listValue) {
        return listValue != null && !listValue.isEmpty() && redissonClient.getList(key).addAll(listValue);
    }

    @Override
    public <T> boolean setList(String key, Collection<T> listValue, Long expiration) {
        if (listValue == null || listValue.isEmpty()) {
            return false;
        }
        if (expiration == null || expiration <= 0) {
            return setList(key, listValue);
        } else {
            RList<T> rList = redissonClient.getList(key);
            boolean status = rList.addAll(listValue);
            rList.expire(expiration, TimeUnit.SECONDS);
            return status;
        }
    }

    @Override
    public <T> List<T> getList(String key) {
        RList<T> list = redissonClient.getList(key);
        return list.readAll();
    }

    @Override
    public void delete(String key) {
        RBucket<Object> bucket = redissonClient.getBucket(key);
        bucket.delete();
    }

    @Override
    public RedissonClient getRedissonClient() {
        return this.redissonClient;
    }

}
