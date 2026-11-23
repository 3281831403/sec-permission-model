from perm.rbac import (
    allow,
    audit_grant,
    deny_wins,
    effective_permissions,
    expand_roles,
    perm_batch,
    resource_match,
    validate_graph,
)


def role_graph():
    return {
        "viewer": {"parents": [], "disabled": False},
        "ops": {"parents": ["viewer"], "disabled": False},
        "admin": {"parents": ["ops"], "disabled": False},
        "banned": {"parents": [], "disabled": True},
        "auditor": {"parents": [], "disabled": False},
    }


def permissions():
    return {
        "viewer": {"allow": [("read", "docs/report")], "deny": []},
        "ops": {"allow": [("read", "ops/status")], "deny": []},
        "admin": {"allow": [("write", "finance/ledger")], "deny": []},
        "banned": {"allow": [("read", "finance/report")], "deny": []},
        "auditor": {
            "allow": [("read", "finance/ledger")],
            "deny": [("read", "finance/ledger")],
        },
    }


def policy():
    return {
        "roles": role_graph(),
        "permissions": permissions(),
        "users": {
            "alice": {"roles": ["admin"], "disabled": False},
            "bob": {"roles": ["viewer"], "disabled": False},
            "carol": {"roles": ["viewer"], "disabled": True},
            "dave": {"roles": ["banned"], "disabled": False},
            "frank": {"roles": ["auditor"], "disabled": False},
        },
    }


def test_expand_roles_follows_multi_level_inheritance():
    assert expand_roles({"roles": ["admin"]}, role_graph()) == {
        "admin",
        "ops",
        "viewer",
    }


def test_expand_roles_terminates_on_cycle():
    graph = {"a": {"parents": ["b"]}, "b": {"parents": ["a"]}}
    assert expand_roles({"roles": ["a"]}, graph) == {"a", "b"}


def test_resource_match_rejects_same_prefix():
    assert resource_match("finance", "finance-report") is False
    assert resource_match("docs/report", "docs/report-secret") is False
    assert resource_match("finance", "finance") is True


def test_resource_wildcard_does_not_cross_segments():
    assert resource_match("docs/*", "docs/a/b") is False
    assert resource_match("*", "a/b") is False
    assert resource_match("docs/*/view", "docs/a/b/view") is False
    assert resource_match("docs/*", "docs/a") is True


def test_deny_wins_even_when_allow_is_non_empty():
    allows = [("read", "docs/report")]
    denies = [("read", "docs/report")]
    assert deny_wins(allows, denies) is True
    assert deny_wins([], denies) is True
    assert deny_wins(allows, []) is False


def test_disabled_user_is_denied_even_with_allow_rule():
    assert allow("carol", "read", "docs/report", policy()) is False


def test_effective_permissions_ignores_disabled_roles():
    assert effective_permissions("dave", policy()) == set()


def test_validate_graph_reports_unknown_parent():
    graph = {"viewer": {"parents": []}, "typo": {"parents": ["viewr"]}}
    assert validate_graph(graph) == ["unknown parent: typo -> viewr"]


def test_audit_grant_names_source_role():
    assert audit_grant("alice", policy()) == [
        "admin:write:finance/ledger",
        "ops:read:ops/status",
        "viewer:read:docs/report",
    ]


def test_perm_batch_keeps_requests_independent():
    requests = [
        {
            "id": "admin-write",
            "user": "alice",
            "action": "write",
            "resource": "finance/ledger",
        },
        {
            "id": "banned-write",
            "user": "dave",
            "action": "write",
            "resource": "finance/ledger",
        },
        {
            "id": "viewer-read",
            "user": "bob",
            "action": "read",
            "resource": "docs/report",
        },
    ]
    assert perm_batch(requests, policy()) == {
        "admin-write": True,
        "banned-write": False,
        "viewer-read": True,
    }


def test_single_role_has_only_its_own_permission():
    user = {"roles": ["viewer"], "disabled": False}
    assert expand_roles(user, role_graph()) == {"viewer"}
    assert effective_permissions("bob", policy()) == {("read", "docs/report")}


def test_two_level_inheritance_unions_permissions():
    assert effective_permissions("alice", policy()) == {
        ("read", "docs/report"),
        ("read", "ops/status"),
        ("write", "finance/ledger"),
    }


def test_deny_rule_overrides_allow_rule():
    assert allow("frank", "read", "finance/ledger", policy()) is False


def test_disabled_user_is_denied_everywhere():
    requests = [
        {
            "id": "one",
            "user": "carol",
            "action": "read",
            "resource": "docs/report",
        }
    ]
    assert allow("carol", "read", "docs/report", policy()) is False
    assert perm_batch(requests, policy()) == {"one": False}


def test_perm_batch_matches_individual_decisions():
    current = policy()
    requests = [
        {
            "id": "a",
            "user": "alice",
            "action": "write",
            "resource": "finance/ledger",
        },
        {
            "id": "b",
            "user": "dave",
            "action": "write",
            "resource": "finance/ledger",
        },
        {
            "id": "c",
            "user": "frank",
            "action": "read",
            "resource": "finance/ledger",
        },
        {
            "id": "d",
            "user": "bob",
            "action": "read",
            "resource": "finance/report",
        },
    ]
    first_batch = perm_batch(requests[:2], current)
    second_batch = perm_batch(requests[2:], current)
    assert set(first_batch) == {"a", "b"}
    assert set(second_batch) == {"c", "d"}
    for request in requests:
        expected = allow(
            request["user"],
            request["action"],
            request["resource"],
            current,
        )
        actual = first_batch.get(request["id"], second_batch.get(request["id"]))
        assert actual is expected
