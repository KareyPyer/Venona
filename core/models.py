from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

class SearchResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    url: str
    snippet: str
    source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_html_hash: Optional[str] = None # Pour la chain of custody

class IOC(BaseModel):
    value: str
    type: str # EMAIL, IPV4, DOMAIN, URL, PHONE, HASH
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)

class Leak(BaseModel):
    ioc: IOC
    signature_type: str # PASSWORD, API_KEY, IBAN, SSN, etc.
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    snippet: str
    source_url: str