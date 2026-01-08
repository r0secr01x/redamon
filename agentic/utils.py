"""
RedAmon Agent Utility Functions

Helper functions for the LangGraph agent orchestrator.
Includes session management, config creation, and response extraction.
"""

from typing import Dict, Any, List, TYPE_CHECKING

from state import AgentState

if TYPE_CHECKING:
    from langgraph.checkpoint.memory import MemorySaver



_checkpointer: "MemorySaver | None" = None


def set_checkpointer(cp: "MemorySaver") -> None:
    """Set the checkpointer reference (called by orchestrator)."""
    global _checkpointer
    _checkpointer = cp


def get_checkpointer() -> "MemorySaver | None":
    """Get the checkpointer reference."""
    return _checkpointer


def get_thread_id(user_id: str, project_id: str, session_id: str) -> str:
    """
    Create a unique thread_id for the checkpointer from identifiers.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier

    Returns:
        Combined thread_id string for checkpointer
    """
    return f"{user_id}:{project_id}:{session_id}"


def parse_thread_id(thread_id: str) -> tuple[str, str, str]:
    """
    Parse a thread_id back into its components.

    Args:
        thread_id: Combined thread_id string

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    parts = thread_id.split(":", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "unknown", "unknown", thread_id


def list_sessions(user_id: str, project_id: str) -> List[str]:
    """
    List all session_ids for a user/project.

    Args:
        user_id: User identifier
        project_id: Project identifier

    Returns:
        List of session_ids
    """
    prefix = f"{user_id}:{project_id}:"
    sessions = []

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        for thread_id in cp.storage.keys():
            if thread_id.startswith(prefix):
                session_id = thread_id[len(prefix):]
                sessions.append(session_id)

    return sessions


def clear_session(user_id: str, project_id: str, session_id: str) -> None:
    """
    Clear a specific session from the checkpointer.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage') and thread_id in cp.storage:
        del cp.storage[thread_id]


def get_session_count() -> int:
    """Get total number of active sessions."""
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def get_message_count(user_id: str, project_id: str, session_id: str) -> int:
    """
    Get the number of messages in a session.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier

    Returns:
        Number of messages in the session
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage') and thread_id in cp.storage:
        checkpoint = cp.storage.get(thread_id)
        if checkpoint and 'channel_values' in checkpoint:
            messages = checkpoint['channel_values'].get('messages', [])
            return len(messages)

    return 0


def create_config(
    user_id: str,
    project_id: str,
    session_id: str
) -> dict:
    """
    Create config for graph invocation with checkpointer thread_id.

    Config contains:
    - thread_id: For MemorySaver checkpointer (session persistence)
    - user_id, project_id, session_id: For logging in nodes

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier for conversation continuity

    Returns:
        Config dict for graph.invoke()
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    return {
        "configurable": {
            "thread_id": thread_id,
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id
        }
    }


def get_config_values(config: dict) -> tuple[str, str, str]:
    """
    Extract user_id, project_id, session_id from config.

    Use in nodes for logging:
        user_id, project_id, session_id = get_config_values(config)
        logger.info(f"[{user_id}/{project_id}/{session_id}] Processing...")

    Args:
        config: The config dict passed to graph nodes

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    configurable = config.get("configurable", {})
    return (
        configurable.get("user_id", "unknown"),
        configurable.get("project_id", "unknown"),
        configurable.get("session_id", "unknown")
    )


def extract_response(state: AgentState) -> Dict[str, Any]:
    """
    Extract the response data from the final state.

    Args:
        state: The final agent state after execution

    Returns:
        Dictionary with answer, tool_used, tool_output, and error fields
    """
    return {
        "answer": state.get("final_answer", ""),
        "tool_used": state.get("tool_used"),
        "tool_output": state.get("tool_output"),
        "error": state.get("error")
    }
