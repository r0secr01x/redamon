"""Phase-related helpers for the orchestrator."""

import json
import asyncio
import logging
from typing import Tuple

from pydantic import ValidationError
from langchain_core.messages import SystemMessage, HumanMessage

from state import AttackPathClassification
from prompts import ATTACK_PATH_CLASSIFICATION_PROMPT
from .json_utils import normalize_content, extract_json

logger = logging.getLogger(__name__)


async def classify_attack_path(
    llm,
    objective: str,
    max_retries: int = 3
) -> Tuple[str, str]:
    """
    Use LLM to classify the attack path type and required phase from user objective.

    Returns validated AttackPathType using Pydantic model.
    Includes retry logic with exponential backoff for resilience.

    Args:
        llm: The LLM instance to use for classification
        objective: User's objective/request text
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        Tuple of (attack_path_type, required_phase):
        - attack_path_type: "cve_exploit" or "brute_force_credential_guess"
        - required_phase: "informational", "exploitation", or "post_exploitation"
    """
    prompt = ATTACK_PATH_CLASSIFICATION_PROMPT.format(objective=objective)

    messages = [
        SystemMessage(content="You are an attack path classifier. Output only valid JSON."),
        HumanMessage(content=prompt)
    ]

    last_error = None

    for attempt in range(max_retries):
        try:
            response = await llm.ainvoke(messages)
            json_str = extract_json(normalize_content(response.content))

            if json_str:
                data = json.loads(json_str)
                classification = AttackPathClassification.model_validate(data)

                # Use LLM-determined required_phase from classification
                required_phase = classification.required_phase

                logger.info(
                    f"Attack path classified as '{classification.attack_path_type}' "
                    f"(confidence: {classification.confidence:.2f}, "
                    f"service: {classification.detected_service}, "
                    f"required_phase: {required_phase}, attempt: {attempt + 1})"
                )

                return classification.attack_path_type, required_phase
            else:
                last_error = "No valid JSON found in response"
                logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        except json.JSONDecodeError as e:
            last_error = f"JSON decode error: {e}"
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        except ValidationError as e:
            last_error = f"Pydantic validation error: {e}"
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        except Exception as e:
            last_error = f"Unexpected error: {e}"
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        # Exponential backoff before retry (100ms, 200ms, 400ms)
        if attempt < max_retries - 1:
            await asyncio.sleep(0.1 * (2 ** attempt))

    logger.error(f"Failed to classify attack path after {max_retries} attempts: {last_error}")
    return "cve_exploit", "informational"  # Safe default - start with recon


def determine_phase_for_new_objective(
    required_phase: str,
    current_phase: str,
) -> str:
    """
    Determine appropriate phase for new objective based on LLM-classified required_phase.

    Per user preference:
    - Auto-downgrade to informational (no approval needed)
    - Require approval for exploitation/post-exploitation upgrades

    Args:
        required_phase: The LLM-classified required phase (from classify_attack_path)
        current_phase: The current phase before this objective

    Returns:
        The phase to transition to for this objective
    """
    # SAFE AUTO-TRANSITION: Downgrade to informational without approval
    if required_phase == "informational" and current_phase in ["exploitation", "post_exploitation"]:
        logger.info("Auto-downgrading phase to informational for new objective (no approval needed)")
        return "informational"

    # Keep current phase if already there (avoid redundant transitions)
    if required_phase == current_phase:
        logger.info(f"Staying in {current_phase} phase for new objective")
        return current_phase

    # For exploitation/post-exploitation: stay in informational and let agent request with approval
    if required_phase in ["exploitation", "post_exploitation"]:
        logger.info(f"New objective needs {required_phase}, starting in informational (agent will request transition)")
        return "informational"

    # Default to informational (safest)
    return "informational"
