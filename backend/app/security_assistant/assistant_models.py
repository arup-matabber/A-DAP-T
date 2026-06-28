from pydantic import BaseModel
from typing import Any, Dict

class AssistantChatRequest(BaseModel):
    question: str
    scan_result: Dict[str, Any]

class AssistantChatResponse(BaseModel):
    answer: str