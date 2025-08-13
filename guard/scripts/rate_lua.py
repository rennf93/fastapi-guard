# guard/scripts/rate_lua.py
# Lua script for atomic rate limiting operations in Redis
# This ensures all operations happen atomically, preventing race conditions
RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

-- Current TS
redis.call('ZADD', key, now, now)

-- Remove TS outside the window
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- Count requests in the window
local count = redis.call('ZCARD', key)

-- Set expiry
redis.call('EXPIRE', key, window * 2)

return count
"""
