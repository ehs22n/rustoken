class RustToken:
    """
    
    Usage:
    

```python
from rustoken import RustToken

    jwt = RustToken("MY-SECRET-KEY") # better to use .env file
    access = jwt.create_token(new_user.id, 24 * 60 * 60) # 1 day exp
    refresh = jwt.create_token(new_user.id, 24 * 60 * 60 * 7) # 7 day exp
    return {"refresh_token": refresh, "access_token": access}


```

---

> NOTE: The expiration time is in seconds

    
    """
    def create_token(user_id: int, ttl_time: int):
        """
        Create (access && refresh token)
        
        Usage:
        seven_day = 24 * 60 * 60 * 7
        .create_token(12, seven_day)
        # 12 is user id
        
        """
        ...
    
    
    def decode(token: str) -> str:
        """decode tokens"""
        ...
       


def secret_key() -> str:
    """Generate Secret-key"""
    ...
