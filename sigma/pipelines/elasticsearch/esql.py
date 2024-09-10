# pylint: disable=too-many-lines
import re
from textwrap import dedent

from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.processing.pipeline import ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import QueryTemplateTransformation
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques
from typing import Dict, List
from sigma.rule import SigmaRuleTag

class EsqlProcessingPipeline(ProcessingPipeline):
    def _convert_tags(self, tags: List[SigmaRuleTag]) -> List[Dict]:
        attack_tags = [t for t in tags if t.namespace == "attack"]
        if not len(attack_tags) >= 2:
            return []

        techniques = [
            tag.name.upper() for tag in attack_tags if re.match(r"[tT]\d{4}", tag.name)
        ]
        tactics = [
            tag.name.lower()
            for tag in attack_tags
            if not re.match(r"[tT]\d{4}", tag.name)
        ]

        output = []
        for tactic, technique in zip(tactics, techniques):
            if (
                not tactic or not technique
            ):  # Only add threat if tactic and technique is known
                continue

            try:
                if "." in technique:  # Contains reference to Mitre Att&ck subtechnique
                    sub_technique = technique
                    technique = technique[0:5]
                    sub_technique_name = mitre_attack_techniques[sub_technique]

                    sub_techniques = [
                        {
                            "id": sub_technique,
                            "reference": f"https://attack.mitre.org/techniques/{sub_technique.replace('.', '/')}",
                            "name": sub_technique_name,
                        }
                    ]
                else:
                    sub_techniques = []

                tactic_id = [
                    id
                    for (id, name) in mitre_attack_tactics.items()
                    if name == tactic.replace("_", "-")
                ][0]
                technique_name = mitre_attack_techniques[technique]
            except (IndexError, KeyError):
                # Occurs when Sigma Mitre Att&ck list is out of date
                continue

            output.append({
                "tactic": {
                    "id": tactic_id,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}",
                    "name": tactic.title().replace("_", " "),
                },
                "framework": "MITRE ATT&CK",
                "technique": [
                    {
                        "id": technique,
                        "reference": f"https://attack.mitre.org/techniques/{technique}",
                        "name": technique_name,
                        "subtechnique": sub_techniques,
                    }
                ],
            })

        return output
    
    def _convert_indices(self, indices: List[str] | str) -> str:
        if not isinstance(indices, str):
            return ESQLBackend.preprocess_indices(indices)

        return indices
    
    def __init__(
        self,
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m", 
        *args,
        **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.vars = {
            "convert_tags": self._convert_tags,
            "convert_indices": self._convert_indices,
            "schedule_interval": schedule_interval,
            "schedule_interval_unit": schedule_interval_unit,
            "severity_risk_mapping": {
                "INFORMATIONAL": 1,
                "LOW": 21,
                "MEDIUM": 47,
                "HIGH": 73,
                "CRITICAL": 99,
            },
        }

def esql_kibana_ndjson() -> EsqlProcessingPipeline:
    return EsqlProcessingPipeline(
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=QueryTemplateTransformation(
                    dedent(
                        """
                        {% set query_json = {
                            "query": {
                                "esql": query
                            },
                            "index": {
                                "title": pipeline.vars.convert_indices(pipeline.state.index),
                                "timeFieldName": "@timestamp",
                                "sourceFilters": [],
                                "type": "esql",
                                "fieldFormats": {},
                                "runtimeFieldMap": {},
                                "allowNoIndex": False,
                                "name": pipeline.vars.convert_indices(pipeline.state.index),
                                "allowHidden": False,
                            },
                            "filter": [],
                        } -%}
                        {
                            "attributes": {
                                "columns": [],
                                "description": "{{ rule.description if rule.description is not none else "No description" }}",
                                "grid": {},
                                "hideChart": false,
                                "isTextBasedQuery": true,
                                "kibanaSavedObjectMeta": {
                                    "searchSourceJSON": {{ query_json | tojson | tojson }}
                                },
                                "sort": [
                                    [
                                        "@timestamp",
                                        "desc"
                                    ]
                                ],
                                "timeRestore": false,
                                "title": "SIGMA - {{ rule.title }}",
                                "usesAdHocDataView": false
                            },
                            "id": "{{ rule.id }}",
                            "managed": false,
                            "references": [],
                            "type": "search",
                            "typeMigrationVersion": "10.3.0"
                        }
                        """
                    ).strip()
                )
            ),
        ]
    )

def esql_siem_rule(
    schedule_interval: int = 5,
    schedule_interval_unit: str = "m",
) -> EsqlProcessingPipeline:
    return EsqlProcessingPipeline(
        schedule_interval=schedule_interval,
        schedule_interval_unit=schedule_interval_unit,
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=QueryTemplateTransformation(
                    dedent(
                        """
                        {
                            "name": "SIGMA - {{ rule.title }}",
                            "tags": [{% for tag in rule.tags %}"{{ tag.namespace }}-{{ tag.name }}"{% if not loop.last %},{% endif %}{% endfor %}],
                            "enabled": true,
                            "consumer": "siem",
                            "throttle": null,
                            "schedule": {
                                "interval": "{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}"
                            },
                            "params": {
                                "author": {{ rule.author if rule.author is not none else [] }},
                                "description": "{{ rule.description if rule.description is not none else "No description" }}",
                                "ruleId": "{{ rule.id }}",
                                "falsePositives": {{ rule.falsepositives }},
                                "from": "now-{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}",
                                "immutable": false,
                                "license": "DRL",
                                "outputIndex": "",
                                "meta": {
                                    "from": "1m"
                                },
                                "maxSignals": 100,
                                "relatedIntegrations": [],
                                "requiredFields": [],
                                "riskScore": {{ pipeline.vars.severity_risk_mapping[rule.level.name] if rule.level is not none else 21 }},
                                "riskScoreMapping": [],
                                "setup": "",
                                "severity": "{{ rule.level.name.lower() if rule.level is not none else "low" }}",
                                "severityMapping": [],
                                "threat": {{ pipeline.vars.convert_tags(rule.tags) }},
                                "to": "now",
                                "references": {{ rule.references if rule.references is not none else [] }},
                                "version": 1,
                                "exceptionsList": [],
                                "type": "esql",
                                "language": "esql",
                                "query": {{ query | tojson }}
                            },
                            "rule_type_id": "siem.esqlRule",
                            "notify_when": "onActiveAlert",
                            "actions": []
                        }
                        """
                    ).strip()
                )
            ),
        ]
    )

def esql_siem_rule_ndjson(
    schedule_interval: int = 5,
    schedule_interval_unit: str = "m",
) -> EsqlProcessingPipeline:
    return EsqlProcessingPipeline(
        schedule_interval=schedule_interval,
        schedule_interval_unit=schedule_interval_unit,
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=QueryTemplateTransformation(
                    dedent(
                        """
                        {
                            "id": "{{ rule.id }}",
                            "name": "SIGMA - {{ rule.title }}",
                            "tags": {% if rule.tags is not none %}[{% for tag in rule.tags %}"{{ tag.namespace }}-{{ tag.name }}"{% if not loop.last %}, {% endif %}{% endfor %}]{% endif %},
                            "interval": "{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}",
                            "enabled": true,
                            "description": "{{ rule.description if rule.description is not none else "No description" }}",
                            "risk_score": {{ pipeline.vars.severity_risk_mapping[rule.level.name] if rule.level is not none else 21 }},
                            "severity": "{{ rule.level.name.lower() if rule.level is not none else "low" }}",
                            "note": "",
                            "license": "DRL",
                            "output_index": "",
                            "meta": {
                                "from": "1m"
                            },
                            "investigation_fields": {},
                            "author": {{ rule.author if rule.author is not none else [] }},
                            "false_positives": {{ rule.falsepositives }},
                            "from": "now-{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}",
                            "rule_id": "{{ rule.id }}",
                            "max_signals": 100,
                            "risk_score_mapping": [],
                            "severity_mapping": [],
                            "threat": {{ pipeline.vars.convert_tags(rule.tags) }},
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
                            "query": {{ query | tojson }},
                            "actions": []
                        }
                        """
                    ).strip()
                )
            ),
        ]
    )
