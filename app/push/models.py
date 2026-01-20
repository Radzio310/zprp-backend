from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class PushRegisterRequest(BaseModel):
    installation_id: str
    token_type: str
    token: str
    platform: Optional[str] = None
    app_variant: Optional[str] = None

class PushScheduleItem(BaseModel):
    send_at_utc: str  # ISO UTC
    title: str
    body: str
    data: Dict[str, Any] = Field(default_factory=dict)

class PushScheduleBulkRequest(BaseModel):
    installation_id: str
    items: List[PushScheduleItem] = Field(default_factory=list)

class PushClearRequest(BaseModel):
    installation_id: str
