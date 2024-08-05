# fastapi_guard/models.py
from pydantic import BaseModel
from typing import List, Optional



class SecurityConfig(BaseModel):
    whitelist: Optional[List[str]] = None
    blacklist: List[str] = []