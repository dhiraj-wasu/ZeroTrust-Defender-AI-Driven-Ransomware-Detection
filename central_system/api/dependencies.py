from typing import AsyncGenerator
from fastapi import Depends
from core.llm_intelligence import LLMIntelligence
from core.forensic_correlator import ForensicCorrelator
from core.coordination_engine import CoordinationEngine
from core.adaptive_learner import AdaptiveLearner
from agents.agent_manager import AgentManager
from agents.command_dispatcher import CommandDispatcher
from models.database import DatabaseManager
from config.settings import settings

# Dependency injection setup
async def get_database() -> AsyncGenerator[DatabaseManager, None]:
    """Database dependency"""
    db = DatabaseManager(settings.DATABASE_URL)
    await db.initialize()
    try:
        yield db
    finally:
        pass

async def get_agent_manager(db: DatabaseManager = Depends(get_database)) -> AgentManager:
    """Agent manager dependency"""
    return AgentManager(db)

async def get_command_dispatcher(agent_manager: AgentManager = Depends(get_agent_manager)) -> CommandDispatcher:
    """Command dispatcher dependency"""
    return CommandDispatcher(agent_manager)

async def get_llm_intelligence() -> LLMIntelligence:
    """LLM intelligence dependency"""
    return LLMIntelligence()

async def get_forensic_correlator(db: DatabaseManager = Depends(get_database)) -> ForensicCorrelator:
    """Forensic correlator dependency"""
    return ForensicCorrelator(db)

async def get_adaptive_learner(db: DatabaseManager = Depends(get_database)) -> AdaptiveLearner:
    """Adaptive learner dependency"""
    return AdaptiveLearner(db)

async def get_coordination_engine(
    agent_manager: AgentManager = Depends(get_agent_manager),
    command_dispatcher: CommandDispatcher = Depends(get_command_dispatcher)
) -> CoordinationEngine:
    """Coordination engine dependency"""
    return CoordinationEngine(agent_manager, command_dispatcher)