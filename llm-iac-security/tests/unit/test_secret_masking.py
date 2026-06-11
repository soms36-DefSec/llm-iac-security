from iac.models import IaCResource, IaCTemplate
from static_analysis.base_rule import mask_secret
from static_analysis.rules.generic_secret_rules import HardcodedSecretRule


def test_mask_secret_does_not_expose_full_value():
    secret = "ExamplePassword123"
    masked = mask_secret(secret)
    assert secret not in masked
    assert masked.startswith("Ex")
    assert masked.endswith("23")


def test_secret_rule_masks_evidence():
    template = IaCTemplate(
        iac_type="terraform",
        source_path="main.tf",
        resources=[
            IaCResource(
                logical_id="aws_db_instance.db",
                resource_type="aws_db_instance",
                provider="aws",
                properties={"password": "ExamplePassword123"},
            )
        ],
    )
    finding = HardcodedSecretRule().scan(template)[0]
    assert "ExamplePassword123" not in finding.evidence
    assert "Ex***23" in finding.evidence


def test_secret_rule_ignores_variable_references():
    template = IaCTemplate(
        iac_type="terraform",
        source_path="main.tf",
        resources=[
            IaCResource(
                logical_id="aws_db_instance.db",
                resource_type="aws_db_instance",
                provider="aws",
                properties={"password": "${var.db_password}"},
            )
        ],
    )
    assert HardcodedSecretRule().scan(template) == []
