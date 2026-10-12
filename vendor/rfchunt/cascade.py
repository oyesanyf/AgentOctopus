"""
Discovery Cascade Engine:
Implements PortSwigger's recursive discovery feedback loop.
Interrogates confirmed desync findings and anomalies with dual prompts:
1. "Look at the observed behavior and consider 1-3 plausible hypotheses that explain it.
    Do any of these hypotheses have security implications beyond this trigger?
    Extrapolate beyond the attack class to the logical extreme."
2. "You're not thinking big enough."
Extracts novel paradigms (Shared-Parser Confusion, Range Cache Poisoning, Status-Line Injection)
and automatically feeds generated second-order probes back into the database.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from database import Database
from model_adapter import ModelFusionAdapter

logger = logging.getLogger("terminator.cascade")


class DiscoveryCascade:
    """
    Extrapolates findings to uncover undiscovered branches on the vulnerability tree.
    """

    SYSTEM_INSTRUCTION = """
You are a principal protocol security researcher specializing in HTTP desync, parser differentials,
and structural protocol flaws.
Your objective is to extrapolate from an observed server anomaly or desync finding into broader,
undiscovered attack classes (e.g. Shared-Parser Confusion, Range Cache Poisoning, Status-Line Injection).
Rules:
1. Focus on the root architectural cause: why did the server behave this way?
2. Did the server misapply a response-parsing rule to a request?
3. Synthesize 1 to 3 new attack hypotheses and concrete HTTP request probes.
4. Output strict JSON:
   {
     "category": "shared_parser_confusion | range_cache_poisoning | status_line_injection | general",
     "hypothesis": "...",
     "suggested_probes": [
        {"rationale": "...", "raw_request": "...", "is_clean": true/false}
     ]
   }
"""

    def __init__(
        self,
        preferred_model: Optional[str] = None,
        use_fusion: bool = False,
        db: Optional[Database] = None,
    ):
        self.adapter = ModelFusionAdapter(preferred_model=preferred_model, use_fusion=use_fusion)
        self.db = db

    def cascade_from_finding(
        self,
        finding_details: Dict[str, Any],
        eval_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Takes an evaluation finding or anomaly, prompts the model for architectural hypotheses,
        pushes with 'You're not thinking big enough', and queues new probes.
        """
        raw_evidence = finding_details.get("raw_evidence", "")
        rationale = finding_details.get("rationale", "")
        rfc_fragment = finding_details.get("rfc_fragment", "")
        details = finding_details.get("details", "")

        user_prompt = f"""
OBSERVED SECURITY FINDING / ANOMALY:
- Details: {details}
- Initial Hypothesis: {rationale}
- Relevant RFC Fragment: {rfc_fragment}
- Observed Evidence Snippet:
{raw_evidence[:600]}

Look at the observed behavior and consider 1-3 plausible hypotheses that explain it.
Do any of these hypotheses have security implications beyond this desync trigger?
Extrapolate beyond the attack class to the logical extreme.
Think about whether the parser shares request and response logic (Shared-Parser Confusion).
"""

        try:
            # Step 1: Initial hypothesis generation
            probes_data = self.adapter.generate_json(self.SYSTEM_INSTRUCTION, user_prompt)
            if not probes_data:
                return None

            # Handle format where model returned a list of items vs a dict
            if isinstance(probes_data, list):
                norm_probes = []
                for p in probes_data:
                    if isinstance(p, dict):
                        norm_probes.append(p)
                    elif isinstance(p, str) and p.strip():
                        norm_probes.append({"rationale": p.strip(), "raw_request": "", "is_clean": False})
                suggested_probes = norm_probes
                category = "shared_parser_confusion" if any("parser" in str(p.get("rationale", "")).lower() for p in norm_probes if isinstance(p, dict)) else "general"
                hypothesis_text = norm_probes[0].get("rationale", "Extrapolated cascade hypothesis") if (norm_probes and isinstance(norm_probes[0], dict)) else "General protocol extrapolation"
            elif isinstance(probes_data, dict):
                category = probes_data.get("category", "general")
                hypothesis_text = probes_data.get("hypothesis", "Extrapolated cascade hypothesis")
                raw_suggested = probes_data.get("suggested_probes", [])
                suggested_probes = [p if isinstance(p, dict) else {"rationale": str(p), "raw_request": "", "is_clean": False} for p in raw_suggested]
            else:
                category = "general"
                hypothesis_text = str(probes_data)
                suggested_probes = []

            # Step 2: Push with 'You're not thinking big enough'
            extrapolated_prompt = (
                f"{user_prompt}\n\n"
                f"Previous hypothesis: {hypothesis_text}\n\n"
                f"You're not thinking big enough! "
                f"What if ANY response-processing feature can be exploited by an incoming request? "
                f"Provide more radical raw HTTP templates targeting this mechanism."
            )

            radical_probes = self.adapter.generate_json(self.SYSTEM_INSTRUCTION, extrapolated_prompt)
            if radical_probes and isinstance(radical_probes, list):
                for rp in radical_probes:
                    if isinstance(rp, dict):
                        suggested_probes.append(rp)
                    elif isinstance(rp, str):
                        suggested_probes.append({"rationale": rp, "raw_request": "", "is_clean": False})

            # Save hypothesis and queue new probes
            if self.db:
                self.db.save_cascade_hypothesis(
                    trigger_eval_id=eval_id,
                    category=category,
                    hypothesis_text=hypothesis_text,
                    suggested_probes=suggested_probes,
                )

                # Queue the second-order probes into database for automatic live testing!
                for probe in suggested_probes:
                    if isinstance(probe, dict):
                        raw_req = probe.get("raw_request")
                        if raw_req:
                            self.db.save_probe(
                                fragment_id=None,
                                rationale=f"[Cascade:{category}] {probe.get('rationale', '')}",
                                raw_request=raw_req,
                                is_clean=probe.get("is_clean", False),
                                source_type="cascade",
                            )

            return {
                "category": category,
                "hypothesis": hypothesis_text,
                "suggested_probes": suggested_probes,
            }

        except Exception as e:
            logger.warning("Cascade extrapolation failed: %s", e)
            return None
