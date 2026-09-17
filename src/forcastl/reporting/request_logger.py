#!/usr/bin/env python3
"""
Request/Response Logger for LLM Validator

Logs all LLM interactions to JSONL for audit and review.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any


class RequestResponseLogger:
    """JSONL logger for LLM request/response interactions"""

    def __init__(self, output_dir: str, enabled: bool = True):
        self.output_dir = output_dir
        self.enabled = enabled
        self.log_file = None

        if self.enabled:
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_file = os.path.join(output_dir, f"llm_interactions_{timestamp}.jsonl")

    def log_interaction(self,
                       prompt: str,
                       response: str,
                       file_path: str,
                       expected_values: Dict[str, Any],
                       score_result: Dict[str, Any],
                       response_time: float,
                       model_name: str = "Unknown") -> None:
        """Log a complete LLM interaction to JSONL"""
        if not self.enabled or not self.log_file:
            return

        interaction = {
            "timestamp": datetime.now().isoformat(),
            "model_name": model_name,
            "file_path": file_path,
            "filename": os.path.basename(file_path) if file_path else "unknown",
            "prompt_length": len(prompt),
            "prompt": prompt,
            "response": response,
            "response_time_seconds": response_time,
            "expected": expected_values,
        }

        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(interaction, ensure_ascii=False, default=str) + '\n')
