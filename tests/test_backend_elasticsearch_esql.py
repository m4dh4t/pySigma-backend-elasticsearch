import pytest
import json

from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.elasticsearch.esql import (
    esql_kibana_ndjson,
    esql_siem_rule_ndjson,
    esql_siem_rule
)

@pytest.fixture
def esql_backend():
    return ESQLBackend()


def test_elasticsearch_esql_and_expression(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['from * metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"']
    )


def test_elasticsearch_esql_or_expression(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ['from * metadata _id, _index, _version | where fieldA=="valueA" or fieldB=="valueB"']
    )


def test_elasticsearch_esql_and_or_expression(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            'from * metadata _id, _index, _version | where (fieldA in ("valueA1", "valueA2")) and (fieldB in ("valueB1", "valueB2"))'
        ]
    )


def test_elasticsearch_esql_or_and_expression(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            'from * metadata _id, _index, _version | where fieldA=="valueA1" and fieldB=="valueB1" or fieldA=="valueA2" and fieldB=="valueB2"'
        ]
    )


def test_elasticsearch_esql_in_expression(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC
                condition: sel
        """
            )
        )
        == ['from * metadata _id, _index, _version | where fieldA in ("valueA", "valueB", "valueC")']
    )


def test_elasticsearch_esql_wildcard_expressions(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - "val*A"
                        - "*valueB"
                        - "valueC*"
                condition: sel
        """
            )
        )
        == [
            'from * metadata _id, _index, _version | where fieldA like "val*A" or ends_with(fieldA, "valueB") or starts_with(fieldA, "valueC")'
        ]
    )


def test_elasticsearch_esql_regex_query(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: "foo.*bar"
                    fieldB: foo
                condition: sel
        """
            )
        )
        == ['from * metadata _id, _index, _version | where fieldA rlike "foo.*bar" and fieldB=="foo"']
    )


def test_elasticsearch_esql_cidr_query(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ['from * metadata _id, _index, _version | where cidr_match(field, "192.168.0.0/16")']
    )


def test_elasticsearch_esql_field_name_with_whitespace(esql_backend: ESQLBackend):
    assert (
        esql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
            )
        )
        == ['from * metadata _id, _index, _version | where `field name`=="value"']
    )

def test_elasticsearch_esql_set_state_index_string(esql_backend: ESQLBackend):
    assert (
        ESQLBackend(
            processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val: logs-test-*
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """
        )).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['from logs-test-* metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"']
    )

def test_elasticsearch_esql_set_state_index_list(esql_backend: ESQLBackend):
    assert (
        ESQLBackend(
            processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val:
                      - logs-test1-*
                      - logs-test2-*
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """
        )).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['from logs-test1-*,logs-test2-* metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"']
    )


def test_elasticsearch_esql_set_state_index_list_single(esql_backend: ESQLBackend):
    assert (
        ESQLBackend(
            processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val:
                      - logs-test-*
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """
        )).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['from logs-test-* metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"']
    )

def test_elasticsearch_esql_set_state_index_list_deduplicate(esql_backend: ESQLBackend):
    assert (
        ESQLBackend(
            processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val:
                      - logs-test-*
                      - logs-test-*
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """
        )).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['from logs-test-* metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"']
    )

def test_elasticsearch_esql_set_state_index_list_wildcard(esql_backend: ESQLBackend):
    assert (
        ESQLBackend(
            processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val:
                      - logs-test-*
                      - "*"
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """
        )).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ['from * metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"']
    )

def test_elasticsearch_esql_ndjson(esql_backend: ESQLBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )
    result = ESQLBackend(esql_kibana_ndjson()).convert(rule)
    assert result[0] == json.dumps({
        'attributes': {
            'columns': [],
            'description': 'No description',
            'grid': {},
            'hideChart': False,
            'isTextBasedQuery': True,
            'kibanaSavedObjectMeta': {
                'searchSourceJSON': '{"filter": [], "index": {"allowHidden": false, "allowNoIndex": false, "fieldFormats": {}, "name": "*", "runtimeFieldMap": {}, "sourceFilters": [], "timeFieldName": "@timestamp", "title": "*", "type": "esql"}, "query": {"esql": "from * metadata _id, _index, _version | where fieldA==\\"valueA\\" and fieldB==\\"valueB\\""}}'
            },
            'sort': [['@timestamp', 'desc']],
            'timeRestore': False,
            'title': 'SIGMA - Test',
            'usesAdHocDataView': False
        },
        'id': 'None',
        'managed': False,
        'references': [],
        'type': 'search',
        'typeMigrationVersion': '10.3.0'
    }, indent=4)


def test_elasticsearch_esql_siemrule(esql_backend: ESQLBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            id: c277adc0-f0c4-42e1-af9d-fab062992156
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )
    result = ESQLBackend(esql_siem_rule()).convert(rule)
    assert result[0] == json.dumps({
        'name': 'SIGMA - Test',
        'tags': [],
        'enabled': True,
        'consumer': 'siem',
        'throttle': None,
        'schedule': {
            'interval': '5m'
        },
        'params': {
            'author': [],
            'description': 'No description',
            'ruleId': 'c277adc0-f0c4-42e1-af9d-fab062992156',
            'falsePositives': [],
            'from': 'now-5m',
            'immutable': False,
            'license': 'DRL',
            'outputIndex': '',
            'meta': {
                'from': '1m'
            },
            'maxSignals': 100,
            'relatedIntegrations': [],
            'requiredFields': [],
            'riskScore': 21,
            'riskScoreMapping': [],
            'setup': '',
            'severity': 'low',
            'severityMapping': [],
            'threat': [],
            'to': 'now',
            'references': [],
            'version': 1,
            'exceptionsList': [],
            'type': 'esql',
            'language': 'esql',
            'query': 'from * metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"'
        },
        'rule_type_id': 'siem.esqlRule',
        'notify_when': 'onActiveAlert',
        'actions': []
    }, indent=4)


def test_elasticsearch_esql_siemrule_ndjson(esql_backend: ESQLBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            id: c277adc0-f0c4-42e1-af9d-fab062992156
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )
    result = ESQLBackend(esql_siem_rule_ndjson()).convert(rule)
    assert result[0] == json.dumps({
        'id': 'c277adc0-f0c4-42e1-af9d-fab062992156',
        'name': 'SIGMA - Test',
        'tags': [],
        'interval': '5m',
        'enabled': True,
        'description': 'No description',
        'risk_score': 21,
        'severity': 'low',
        'note': '',
        'license': 'DRL',
        'output_index': '',
        'meta': {
            'from': '1m'
        },
        'investigation_fields': {},
        'author': [],
        'false_positives': [],
        'from': 'now-5m',
        'rule_id': 'c277adc0-f0c4-42e1-af9d-fab062992156',
        'max_signals': 100,
        'risk_score_mapping': [],
        'severity_mapping': [],
        'threat': [],
        'to': 'now',
        'references': [],
        'version': 1,
        'exceptions_list': [],
        'immutable': False,
        'related_integrations': [],
        'required_fields': [],
        'setup': '',
        'type': 'esql',
        'language': 'esql',
        'query': 'from * metadata _id, _index, _version | where fieldA=="valueA" and fieldB=="valueB"',
        'actions': []
    }, indent=4)
