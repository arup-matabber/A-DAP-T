import os
from typing import Optional


class GeminiService:
    """
    Thin Gemini wrapper for A-DAP-T.

    This service is intentionally separated from scanner logic.
    If Gemini is unavailable, callers should fall back to static templates.
    """

    def __init__(self, model_name: Optional[str] = None):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self._client = None

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _get_client(self):
        if self._client is not None:
            return self._client

        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")

        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError(
                "google-genai package is not installed. "
                "Install it with: pip install google-genai"
            ) from exc

        self._client = genai.Client(api_key=self.api_key)
        return self._client

    def generate_text(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        """
        Generate text from Gemini.

        Returns plain text.
        Raises RuntimeError if Gemini is unavailable or fails.
        """

        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")

        client = self._get_client()

        final_prompt = prompt
        if system_instruction:
            final_prompt = f"{system_instruction.strip()}\n\n{prompt.strip()}"

        try:
            response = client.models.generate_content(
                model=self.model_name,
                contents=final_prompt
            )

            text = getattr(response, "text", None)
            if not text:
                raise RuntimeError("Gemini returned an empty response")

            return text.strip()

        except Exception as exc:
            raise RuntimeError(f"Gemini generation failed: {str(exc)}") from exc