import os
from typing import Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

class Settings:
    """Central system configuration for NetMoniAI-Ransom"""
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/central_system.log"

    # Server Configuration
    SERVER_HOST = os.getenv("CENTRAL_SERVER_HOST", "0.0.0.0")
    SERVER_PORT = int(os.getenv("CENTRAL_SERVER_PORT", "8765"))
    WEBSOCKET_TIMEOUT = int(os.getenv("WEBSOCKET_TIMEOUT", "30"))
    
    # Database Configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///central_intelligence.db")
    
    # Multi-LLM Configuration with fallback
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    LOCAL_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
    
    # Fallback order — you can override via .env (e.g., "gemini,openai,local")
    LLM_FALLBACK_ORDER = os.getenv("LLM_FALLBACK_ORDER", "gemini,openai,local").split(",")
    
    # Security Configuration
    AGENT_AUTH_TOKEN = os.getenv("AGENT_AUTH_TOKEN", "default-secret-token")
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "default-encryption-key")
    
    # Response Configuration
    EMERGENCY_MODE_DURATION = int(os.getenv("EMERGENCY_MODE_DURATION", "3600"))
    HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
    
    # Threat Assessment Thresholds
    CRITICAL_THRESHOLD = float(os.getenv("CRITICAL_THRESHOLD", "8.0"))
    HIGH_THRESHOLD = float(os.getenv("HIGH_THRESHOLD", "6.0"))
    MEDIUM_THRESHOLD = float(os.getenv("MEDIUM_THRESHOLD", "4.0"))

    def get_llm_config(self) -> Dict[str, Any]:
        """Return LLM configuration for LLMIntelligence class"""
        return {
            "gemini_api_key": self.GEMINI_API_KEY,
            "openai_api_key": self.OPENAI_API_KEY,
            "local_llm_url": self.LOCAL_LLM_URL,
            "fallback_order": self.LLM_FALLBACK_ORDER,
        }

# Global settings instance
settings = Settings()
