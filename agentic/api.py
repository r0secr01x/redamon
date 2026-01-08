"""
RedAmon Agent REST API

FastAPI application providing REST endpoints for the agent orchestrator.
Supports session-based conversation continuity.

Endpoints:
    POST /query - Send a question to the agent
    GET /health - Health check
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from orchestrator import AgentOrchestrator
from utils import get_message_count, get_session_count

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

orchestrator: Optional[AgentOrchestrator] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Initializes the orchestrator on startup and cleans up on shutdown.
    """
    global orchestrator

    logger.info("Starting RedAmon Agent API...")

    # Initialize orchestrator
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    logger.info("RedAmon Agent API ready")

    yield

    logger.info("Shutting down RedAmon Agent API...")
    if orchestrator:
        await orchestrator.close()


app = FastAPI(
    title="RedAmon Agent API",
    description="REST API for the RedAmon LangGraph agent with MCP tools and Neo4j integration",
    version="1.0.0",
    lifespan=lifespan
)


class QueryRequest(BaseModel):
    """Request model for agent queries."""
    question: str = Field(..., description="The question to ask the agent", min_length=1)
    user_id: str = Field(..., description="User identifier", min_length=1)
    project_id: str = Field(..., description="Project identifier", min_length=1)
    session_id: str = Field(..., description="Session identifier for conversation continuity", min_length=1)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "question": "Use curl to check http://testphp.vulnweb.com",
                    "user_id": "user1",
                    "project_id": "project1",
                    "session_id": "session-001"
                }
            ]
        }
    }


class QueryResponse(BaseModel):
    """Response model for agent queries."""
    answer: str = Field(..., description="The agent's answer")
    tool_used: Optional[str] = Field(None, description="Name of the tool that was executed")
    tool_output: Optional[str] = Field(None, description="Raw output from the tool")
    session_id: str = Field(..., description="Session identifier (echoed back)")
    message_count: int = Field(..., description="Number of messages in the session")
    error: Optional[str] = Field(None, description="Error message if something went wrong")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    tools_loaded: int
    active_sessions: int


@app.post("/query", response_model=QueryResponse, tags=["Agent"])
async def query(request: QueryRequest):
    """
    Send a question to the agent.

    The agent will:
    1. Load conversation history for the session
    2. Choose and execute the appropriate tool (curl or graph query)
    3. Return the answer with tool execution details
    4. Save the updated conversation to the session

    **Session continuity**: Use the same `session_id` to continue a conversation.
    The agent will remember previous messages and context within the session.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    logger.info(f"Query from {request.user_id}/{request.project_id}/{request.session_id}: {request.question[:50]}...")

    try:
        result = await orchestrator.invoke(
            question=request.question,
            user_id=request.user_id,
            project_id=request.project_id,
            session_id=request.session_id
        )

        message_count = get_message_count(
            request.user_id, request.project_id, request.session_id
        )

        return QueryResponse(
            answer=result.answer,
            tool_used=result.tool_used,
            tool_output=result.tool_output,
            session_id=request.session_id,
            message_count=message_count,
            error=result.error
        )

    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """
    Health check endpoint.

    Returns the API status, version, number of loaded tools, and active sessions.
    """
    tools_count = len(orchestrator.tools) if orchestrator else 0
    sessions_count = get_session_count()

    return HealthResponse(
        status="ok" if orchestrator and orchestrator._initialized else "initializing",
        version="1.0.0",
        tools_loaded=tools_count,
        active_sessions=sessions_count
    )
