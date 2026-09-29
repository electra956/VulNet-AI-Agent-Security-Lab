"""
Test defaults: the unit suite is deterministic and does not depend on a running Ollama server.
Live LLM/embedding tests opt in explicitly (see tests/test_live_llm_rag.py) and skip when Ollama
or the models are unavailable.
"""
import os

os.environ.setdefault("VULNET_USE_LLM", "false")
os.environ.setdefault("VULNET_RAG_EMBEDDINGS", "off")
