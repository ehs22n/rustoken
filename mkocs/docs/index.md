---
title: Rustoken
description: Rustoken Documentaion
canonical_url: "https://github.com/ehs22n/rustoken"
---


<img src="./logo.png" width=100>

# Rustoken

**Rustoken** is a `Python library` written in `Rust` that can create and decode JWT tokens.
This is the first version of the library and it currently supports only the `HS256` algorithm.


---


How to make SECRET-KEY in Rustoken:
```python
from rustoken import secret_key

secret_key = secret_key() # save it to .env file
print(secret_key)
```

---

How to make SECRET-KEY on linux:
```bash
# 32 bytes (256 bits) base64
openssl rand -base64 32   # outputs a base64 string you can store

# or 64 bytes (512 bits)
openssl rand -base64 64
```

---

Usage In Fast-Api:

```python
from rustoken import RustToken

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from . import models, schemas, database

app = FastAPI()


models.Base.metadata.create_all(bind=database.engine)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/make-user/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    new_user = models.User(username=user.username, email=user.email)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    #<------------------------------------------------------->
    jwt = RustToken("MY-SECRET-KEY") # better to use .env file
    access = jwt.create_token(new_user.id, 24 * 60 * 60) # 1 day
    refresh = jwt.create_token(new_user.id, 24 * 60 * 60 * 7) # 7 day exp
    return {"refresh_token": refresh, "access_token": access}

```

---

> NOTE: The expiration time is in seconds

---

How to decode Tokens:
```python
    from rustoken import RustToken

    jwt = RustToken("MY-SECRET-KEY") # better to use .env file

    token = "eyJ0eXAiOiJKV1QiLCJhbGciO..."
    try:
        jwt.decode(token)
    except ValueError:
        # if token is expired it return a ValueError
        ...

```
