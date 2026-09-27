from app.rules.brute_force import BruteForceRule
from app.rules.password_spray import PasswordSprayRule


BRUTE_FORCE_RULE = BruteForceRule()
PASSWORD_SPRAY_RULE = PasswordSprayRule()


RULE_REGISTRY = {
    BRUTE_FORCE_RULE.name: BRUTE_FORCE_RULE,
    PASSWORD_SPRAY_RULE.name: PASSWORD_SPRAY_RULE,
}


def get_rule(rule_name: str):
    """Return a registered detection rule by name."""

    return RULE_REGISTRY.get(rule_name)