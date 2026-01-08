"""
RedAmon Agent State Management

LangGraph state and Pydantic models for the agent orchestrator.
"""

from typing import Annotated, TypedDict, Optional
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """LangGraph state for the agent orchestrator."""
    messages: Annotated[list, add_messages]


class InvokeResponse(BaseModel):
    """Response from agent invocation."""
    answer: str = Field(default="", description="The agent's final answer")
    tool_used: Optional[str] = Field(default=None, description="Name of the tool executed")
    tool_output: Optional[str] = Field(default=None, description="Raw output from the tool")
    error: Optional[str] = Field(default=None, description="Error message if failed")
