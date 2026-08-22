"""
X-Chat — Multi-model crypto analysis interrogation workbench.

Module structure:
    session    — interactive interrogation loop
    llm_router — 3b ↔ 7b ↔ cloud orchestration
    pipe_runner — xcore.exe pipe interface
    case_learner — deep analysis + knowledge DB
    sanitizer  — cloud data sanitization
    api_key    — encrypted cloud credential storage
    intent     — NL → command parsing constants
    config     — project-wide paths and constants
"""

from .session import XChatSession
from .llm_router import LLMRouter
from .case_learner import CaseLearner
from .pipe_runner import run_xcore_pipe
