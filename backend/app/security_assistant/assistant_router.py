from fastapi import APIRouter, Depends, HTTPException
from app.routes import auth
from app.security_assistant.assistant_models import AssistantChatRequest, AssistantChatResponse
from app.security_assistant.assistant_service import SecurityAssistantService

router = APIRouter(prefix="/assistant", tags=["Security Assistant"])

@router.post("/chat", response_model=AssistantChatResponse)
async def chat_with_assistant(
    payload: AssistantChatRequest,
    user=Depends(auth.get_current_user) # Protected tracking alignment consistent with system standards
):
    # Enforce basic authentication guard
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    service = SecurityAssistantService()
    answer_text = service.ask_assistant(payload.question, payload.scan_result)
    
    return AssistantChatResponse(answer=answer_text)