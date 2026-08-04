from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class PushRegisterRequest(BaseModel):
    installation_id: str
    token_type: str
    token: str
    platform: Optional[str] = None
    app_variant: Optional[str] = None
    # Kto jest zalogowany na tym urządzeniu. Starsze wersje aplikacji tego nie
    # wysyłają — wtedy zostaje None i push kierowany po judge_id ich pominie.
    judge_id: Optional[str] = None
    # True = klient świadomie przesłał bieżącą tożsamość; po wylogowaniu można
    # wtedy wyczyścić stare judge_id. Starsze APK zachowują dotychczasowe dane.
    identity_known: bool = False
    province: Optional[str] = None
    notification_prefs: Dict[str, Any] = Field(default_factory=dict)

class PushIdentityRequest(BaseModel):
    installation_id: str
    judge_id: Optional[str] = None
    province: Optional[str] = None
    notification_prefs: Dict[str, Any] = Field(default_factory=dict)

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
