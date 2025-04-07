from pydantic import BaseModel
from typing import List

class User(BaseModel):
    username: str
    email: str
    groups: List[str]  # Groups the user belongs to
