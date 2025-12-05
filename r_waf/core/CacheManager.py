from functools import lru_cache, wraps
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CacheManager:
    def __init__(self, maxsize=32):
        self.maxsize = maxsize
        self.cache_stats = {}
        logger.info(f"CacheManager initialized with maxsize={maxsize}")
    
    def cached(self, func):
        @lru_cache(maxsize=self.maxsize)
        def cached_func(*args, **kwargs):
            return func(*args, **kwargs)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = cached_func(*args, **kwargs)
            
            cache_info = cached_func.cache_info()
            func_name = func.__name__
            self.cache_stats[func_name] = {
                "hits": cache_info.hits,
                "misses": cache_info.misses,
                "size": cache_info.currsize,
                "maxsize": cache_info.maxsize
            }
            
            return result
        
        wrapper.cache_info = cached_func.cache_info
        wrapper.cache_clear = cached_func.cache_clear
        
        return wrapper
    
    def clear_all(self):
        cleared_count = 0
        for func_name, stats in self.cache_stats.items():
            if stats["size"] > 0:
                cleared_count += 1
        self.cache_stats.clear()
        logger.info(f"Cleared {cleared_count} function caches")
        return cleared_count
    
    def get_stats(self):
        return self.cache_stats.copy()
    
    def get_summary(self):
        total_hits = sum(s["hits"] for s in self.cache_stats.values())
        total_misses = sum(s["misses"] for s in self.cache_stats.values())
        total_size = sum(s["size"] for s in self.cache_stats.values())
        
        hit_rate = (total_hits / (total_hits + total_misses) * 100) if (total_hits + total_misses) > 0 else 0
        
        return {
            "total_hits": total_hits,
            "total_misses": total_misses,
            "total_cached_items": total_size,
            "hit_rate_percent": round(hit_rate, 2),
            "functions_cached": len(self.cache_stats)
        }
