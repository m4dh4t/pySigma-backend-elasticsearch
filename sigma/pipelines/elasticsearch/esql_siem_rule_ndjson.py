# pylint: disable=too-many-lines
from textwrap import dedent

from sigma.processing.pipeline import ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import QueryTemplateTransformation


""" Sample as defined in the original finalize_query function
{
    "id": str(rule.id),
    "name": f"SIGMA - {rule.title}",
    "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
    "interval": f"{self.schedule_interval}{self.schedule_interval_unit}",
    "enabled": True,
    "description": (
        rule.description if rule.description is not None else "No description"
    ),
    "risk_score": (
        self.severity_risk_mapping[rule.level.name]
        if rule.level is not None
        else 21
    ),
    "severity": (
        str(rule.level.name).lower() if rule.level is not None else "low"
    ),
    "note": "",
    "license": "DRL",
    "output_index": "",
    "meta": {
        "from": "1m",
    },
    "investigation_fields": {},
    "author": [rule.author] if rule.author is not None else [],
    "false_positives": rule.falsepositives,
    "from": f"now-{self.schedule_interval}{self.schedule_interval_unit}",
    "rule_id": str(rule.id),
    "max_signals": 100,
    "risk_score_mapping": [],
    "severity_mapping": [],
    "threat": list(self.finalize_output_threat_model(rule.tags)),
    "to": "now",
    "references": rule.references,
    "version": 1,
    "exceptions_list": [],
    "immutable": False,
    "related_integrations": [],
    "required_fields": [],
    "setup": "",
    "type": "esql",
    "language": "esql",
    "query": query,
    "actions": [],
}
"""



def esql_siem_rule_ndjson() -> ProcessingPipeline:
    return ProcessingPipeline(
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=QueryTemplateTransformation(
                    dedent("""
                    {
                        "id": "{{ rule.id }}",
                        "name": "SIGMA - {{ rule.title }}",
                        "tags":  {% if rule.tags is not none %}[{% for tag in rule.tags %}"{{ tag.namespace }}-{{ tag.name }}"{% if not loop.last %},{% endif %}{% endfor %}]{% endif %},
                        "interval": "FIXME",
                        "enabled": true,
                        "description": {{ rule.description if rule.description is not none else "No description" }},
                        "risk_score": {{ FIXME if rule.level is not none else 21 }},
                        "severity": "{{ rule.level.name.lower() if rule.level is not none else "low" }}",
                        "note": "",
                        "license": "DRL",
                        "output_index": "",
                        "meta": {
                            "from": "1m",
                        },
                        "investigation_fields": {},
                        "author": {{ rule.author if rule.author is not none else [] }},
                        "false_positives": {{ rule.falsepositives }},
                        "from": "FIXME",
                        "rule_id": "{{ rule.id }}",
                        "max_signals": 100,
                        "risk_score_mapping": [],
                        "severity_mapping": [],
                        "threat": "FIXME",
                        "to": "now",
                        "references": {{ rule.references if rule.references is not none else [] }},
                        "version": 1,
                        "exceptions_list": [],
                        "immutable": false,
                        "related_integrations": [],
                        "required_fields": [],
                        "setup": "",
                        "type": "esql",
                        "language": "esql",
                        "query": "{{ query }}",
                        "actions": [],
                    }""")
                )
            ),
        ]
    )
