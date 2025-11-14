# api/dependencies.py
from typing import Optional

# Global agent instance
_agent_instance = None


def set_agent(agent):
    """Set the global agent instance - called by main.py"""
    global _agent_instance
    _agent_instance = agent

def get_agent():
    """Get the global agent instance - used by API endpoints"""
    return _agent_instance