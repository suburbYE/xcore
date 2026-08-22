"""xchat/vision — Multimodal vision purification for reverse engineering.

Sub-modules:
    ocr_engine   — Network capture OCR, captcha coordinate extraction, entropy
    cfg_parser   — IDA / Binary Ninja CFG semantic analysis

All public functions accept image paths and return structured dicts.
"""

from .ocr_engine import calculate_shannon_entropy, extract_captcha_coordinates, extract_network_capture
from .cfg_parser import analyze_cfg_image

__all__ = [
    "calculate_shannon_entropy",
    "extract_network_capture",
    "extract_captcha_coordinates",
    "analyze_cfg_image",
]
