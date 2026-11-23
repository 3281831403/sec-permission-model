"""Role based access control primitives for the security exercise.

Data model
----------
role_graph
    Mapping of role name to a mapping with optional parents (an iterable of
    role names) and optional disabled (a bool, default False).
user
    Mapping with roles (an iterable of role names) and optional disabled
    (a bool, default False).
policy
    Mapping with roles (a role graph), permissions (role name to a mapping
    with allow and deny, each an iterable of (action, resource_pattern)
    pairs) and users (user name to a user mapping).

Matching tolerance is zero
--------------------------
Actions are literal names or the single wildcard *, resource patterns are
slash separated, and * matches exactly one non-empty path segment. There is
no prefix matching, case folding, fuzzy matching or alias resolution.
"""


def _action_match(pattern, action):
    """Match an action against an exact name or the single wildcard *."""
    return pattern == "*" or pattern == action


def expand_roles(user, role_graph):
    """Return the transitive role closure for a user.

    Direct roles come from user["roles"]. Every parent named in
    role_graph[role]["parents"] is added recursively, so inheritance is
    transitive at any depth and the permissions of all ancestors apply.
    Each role is visited at most once: a cycle must terminate normally
    instead of recursing forever or raising RecursionError. Unknown role
    names are kept so validate_graph can report them. Disabled roles are
    still returned here; filtering disabled roles belongs to the permission
    evaluation functions. Tolerance is zero: names are compared exactly.
    """
    expanded = set()
    stack = list(user.get("roles", ()))
    while stack:
        role = stack.pop()
        if role in expanded:
            continue
        expanded.add(role)
        node = role_graph.get(role)
        if node:
            stack.extend(node.get("parents", ()))
    return expanded


def resource_match(pattern, resource):
    """Return True when resource is covered by a resource pattern.

    Both values are split on /. A * segment matches exactly one non-empty
    segment and never crosses a slash, so docs/* matches docs/a but not
    docs/a/b. Every other segment must be equal, with exact case and no
    leading or trailing slash tolerance. Segment counts must be equal. There
    is no prefix match, no implicit suffix wildcard and no fuzzy comparison,
    because all matching tolerance is zero.
    """
    pattern_segments = pattern.split("/")
    resource_segments = resource.split("/")
    if len(pattern_segments) != len(resource_segments):
        return False
    for pat, seg in zip(pattern_segments, resource_segments):
        if pat == "*":
            if not seg:
                return False
        elif pat != seg:
            return False
    return True


def allow(user, action, resource, policy):
    """Decide whether user may perform action on resource under policy.

    Evaluation order is strict:
    1. An unknown user, or a user whose disabled flag is True, is denied.
    2. Roles are expanded transitively; disabled roles contribute no rules.
    3. A deny rule matching the action and resource from any active role
       denies the request, even when allow rules also match. Deny always
       overrides allow.
    4. Otherwise the request is allowed only if at least one allow rule
       matches. The default is deny.

    An action matches an exact action name or the single wildcard *. A
    resource is matched with resource_match. Tolerance is zero: no prefix,
    role name, case or typo leniency is applied.
    """
    record = policy.get("users", {}).get(user)
    if record is None or record.get("disabled", False):
        return False
    role_graph = policy.get("roles", {})
    permissions = policy.get("permissions", {})
    roles = expand_roles(record, role_graph)
    matched_allows = []
    matched_denies = []
    for role in roles:
        node = role_graph.get(role)
        if node is None or node.get("disabled", False):
            continue
        rules = permissions.get(role, {})
        for action_pat, resource_pat in rules.get("allow", ()):
            if _action_match(action_pat, action) and resource_match(
                resource_pat, resource
            ):
                matched_allows.append((action_pat, resource_pat))
        for action_pat, resource_pat in rules.get("deny", ()):
            if _action_match(action_pat, action) and resource_match(
                resource_pat, resource
            ):
                matched_denies.append((action_pat, resource_pat))
    if deny_wins(matched_allows, matched_denies):
        return False
    return bool(matched_allows)


def deny_wins(allows, denies):
    """Return True whenever the deny collection is non-empty.

    Deny wins even when allows is non-empty: one deny rule is enough to
    reject. Only an empty deny collection returns False. The implementation
    must inspect denies regardless of whether allows is empty; a deny must
    never be ignored just because an allow was found.
    """
    return bool(denies)


def validate_graph(role_graph):
    """Return a deterministic list of structural problems in role_graph.

    For each role visited in sorted order, append at most one empty name
    issue, then one issue for each missing parent in sorted order, then one
    cycle issue when the role can reach itself through parents. The exact
    issue strings are:
    - "empty role name" for a blank role key, with no further checks for it
    - "unknown parent: ROLE -> PARENT" for a parent absent from the graph
    - "cycle: ROLE" once for every role participating in a cycle

    A well formed graph returns an empty list. The input is not mutated.
    """
    issues = []

    def reaches_self(start):
        seen = set()
        stack = [start]
        while stack:
            role = stack.pop()
            for parent in role_graph.get(role, {}).get("parents", ()):
                if parent == start:
                    return True
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        return False

    for role in sorted(role_graph):
        if not role:
            issues.append("empty role name")
            continue
        node = role_graph[role]
        for parent in sorted(node.get("parents", ())):
            if parent not in role_graph:
                issues.append("unknown parent: %s -> %s" % (role, parent))
        if reaches_self(role):
            issues.append("cycle: %s" % role)
    return issues


def effective_permissions(user, policy):
    """Return the allow pairs that remain effective for user under policy.

    Roles are expanded transitively; a disabled user or a disabled role is
    ignored. Each surviving allow pair is returned as the declared
    (action, resource_pattern) tuple. A pair is removed when an active deny
    rule matches its action and resource, so deny overrides allow. The
    result is a set, so duplicate grants collapse. Tolerance is zero.
    """
    record = policy.get("users", {}).get(user)
    if record is None or record.get("disabled", False):
        return set()
    role_graph = policy.get("roles", {})
    permissions = policy.get("permissions", {})
    allows = set()
    denies = []
    for role in expand_roles(record, role_graph):
        node = role_graph.get(role)
        if node is None or node.get("disabled", False):
            continue
        rules = permissions.get(role, {})
        allows.update(rules.get("allow", ()))
        denies.extend(rules.get("deny", ()))
    return {
        (action, resource)
        for action, resource in allows
        if not any(
            _action_match(deny_action, action)
            and resource_match(deny_resource, resource)
            for deny_action, deny_resource in denies
        )
    }


def audit_grant(user, policy):
    """Return sorted evidence lines for grants that survive evaluation.

    Each line has the form role:action:resource and names the source role,
    so a reviewer can trace a permission back to the granting role rather
    than seeing only a final boolean. Disabled users and disabled roles
    produce no lines. Allow pairs cancelled by a deny rule are omitted.
    The result is deterministic, sorted and free of duplicates.
    """
    record = policy.get("users", {}).get(user)
    if record is None or record.get("disabled", False):
        return []
    role_graph = policy.get("roles", {})
    permissions = policy.get("permissions", {})
    grants = []
    denies = []
    for role in expand_roles(record, role_graph):
        node = role_graph.get(role)
        if node is None or node.get("disabled", False):
            continue
        rules = permissions.get(role, {})
        for action, resource in rules.get("allow", ()):
            grants.append((role, action, resource))
        denies.extend(rules.get("deny", ()))
    lines = {
        "%s:%s:%s" % (role, action, resource)
        for role, action, resource in grants
        if not any(
            _action_match(deny_action, action)
            and resource_match(deny_resource, resource)
            for deny_action, deny_resource in denies
        )
    }
    return sorted(lines)


def perm_batch(requests, policy):
    """Evaluate independent requests and return a mapping of id to bool.

    requests is an iterable of mappings with id, user, action and resource
    keys. Every request is evaluated from scratch with allow, so an expanded
    role set or decision from one request never affects another user. A
    later request carrying a duplicate id overwrites the earlier result.
    """
    results = {}
    for request in requests:
        results[request["id"]] = allow(
            request["user"],
            request["action"],
            request["resource"],
            policy,
        )
    return results
