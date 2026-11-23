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
    # Fix 1: walk the parent chain to full transitive depth instead of
    # only adding the first layer of parents.
    # Fix 2: track visited roles in a set so cycles terminate instead of
    # overflowing the recursion stack.
    expanded = set()
    stack = list(user.get("roles", ()))
    while stack:
        role = stack.pop()
        if role in expanded:
            continue
        expanded.add(role)
        node = role_graph.get(role)
        if node is not None:
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
    # Fix 3: compare whole segments with exact equality, never a string
    # prefix check (which would let "finance" match "finance-report").
    # Fix 4: a wildcard segment matches exactly one non-empty segment and
    # never crosses a slash; segment counts must be identical.
    pattern_parts = pattern.split("/")
    resource_parts = resource.split("/")
    if len(pattern_parts) != len(resource_parts):
        return False
    for pattern_part, resource_part in zip(pattern_parts, resource_parts):
        if pattern_part == "*":
            if resource_part == "":
                return False
        elif pattern_part != resource_part:
            return False
    return True


def _action_matches(rule_action, action):
    """The * wildcard matches any action; otherwise names must be equal."""
    return rule_action == "*" or rule_action == action


def _role_is_active(role, role_graph):
    """A role is active when present in the graph and not disabled."""
    node = role_graph.get(role)
    return node is not None and not node.get("disabled", False)


def _active_roles(user, role_graph):
    """Transitive closure with disabled roles removed."""
    return {
        role
        for role in expand_roles(user, role_graph)
        if _role_is_active(role, role_graph)
    }


def _rule_matches(rule, action, resource):
    rule_action, rule_pattern = rule
    return _action_matches(rule_action, action) and resource_match(
        rule_pattern, resource
    )


def _has_matching_deny(roles, policy, action, resource):
    """True when an active role's deny rule matches the request."""
    permissions = policy.get("permissions", {})
    for role in roles:
        for rule in permissions.get(role, {}).get("deny", ()):
            if _rule_matches(rule, action, resource):
                return True
    return False


def _has_matching_allow(roles, policy, action, resource):
    """True when an active role's allow rule matches the request."""
    permissions = policy.get("permissions", {})
    for role in roles:
        for rule in permissions.get(role, {}).get("allow", ()):
            if _rule_matches(rule, action, resource):
                return True
    return False


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
    # Fix 6: reject unknown and explicitly disabled users before any rule
    # evaluation, so a disabled user can never be granted access.
    user_entry = policy.get("users", {}).get(user)
    if user_entry is None or user_entry.get("disabled", False):
        return False

    role_graph = policy.get("roles", {})
    # Fix 7 (shared by every evaluation path): disabled roles contribute
    # no rules to the decision.
    roles = _active_roles(user_entry, role_graph)

    # Fix 5: deny is inspected unconditionally and always overrides allow.
    if _has_matching_deny(roles, policy, action, resource):
        return False
    return _has_matching_allow(roles, policy, action, resource)


def deny_wins(allows, denies):
    """Return True whenever the deny collection is non-empty.

    Deny wins even when allows is non-empty: one deny rule is enough to
    reject. Only an empty deny collection returns False. The implementation
    must inspect denies regardless of whether allows is empty; a deny must
    never be ignored just because an allow was found.
    """
    # Fix 5: deny wins on its own merits; allows is never consulted.
    return len(denies) > 0


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
    # Fix 8: parents absent from the graph are reported instead of being
    # silently swallowed.
    issues = []
    for role in sorted(role_graph):
        if role == "":
            issues.append("empty role name")
            continue

        parents = role_graph[role].get("parents", ())
        for parent in sorted(parents):
            if parent not in role_graph:
                issues.append(f"unknown parent: {role} -> {parent}")

        # Cycle detection with an explicit visited set so a ring terminates
        # instead of recursing forever.
        seen = set()
        stack = list(role_graph[role].get("parents", ()))
        reaches_self = False
        while stack:
            current = stack.pop()
            if current == role:
                reaches_self = True
                break
            if current in seen or current not in role_graph:
                continue
            seen.add(current)
            stack.extend(role_graph[current].get("parents", ()))
        if reaches_self:
            issues.append(f"cycle: {role}")
    return issues


def effective_permissions(user, policy):
    """Return the allow pairs that remain effective for user under policy.

    Roles are expanded transitively; a disabled user or a disabled role is
    ignored. Each surviving allow pair is returned as the declared
    (action, resource_pattern) tuple. A pair is removed when an active deny
    rule matches its action and resource, so deny overrides allow. The
    result is a set, so duplicate grants collapse. Tolerance is zero.
    """
    user_entry = policy.get("users", {}).get(user)
    if user_entry is None or user_entry.get("disabled", False):
        return set()

    role_graph = policy.get("roles", {})
    # Fix 7: expand at full depth and drop disabled roles before collecting
    # any rules.
    roles = _active_roles(user_entry, role_graph)
    permissions = policy.get("permissions", {})

    result = set()
    for role in roles:
        for rule_action, rule_pattern in permissions.get(role, {}).get(
            "allow", ()
        ):
            if _has_matching_deny(roles, policy, rule_action, rule_pattern):
                continue
            result.add((rule_action, rule_pattern))
    return result


def audit_grant(user, policy):
    """Return sorted evidence lines for grants that survive evaluation.

    Each line has the form role:action:resource and names the source role,
    so a reviewer can trace a permission back to the granting role rather
    than seeing only a final boolean. Disabled users and disabled roles
    produce no lines. Allow pairs cancelled by a deny rule are omitted.
    The result is deterministic, sorted and free of duplicates.
    """
    user_entry = policy.get("users", {}).get(user)
    if user_entry is None or user_entry.get("disabled", False):
        return []

    role_graph = policy.get("roles", {})
    roles = _active_roles(user_entry, role_graph)
    permissions = policy.get("permissions", {})

    # Fix 9: keep the source role on every evidence line instead of only
    # recording the final allow/deny outcome.
    lines = set()
    for role in roles:
        for rule_action, rule_pattern in permissions.get(role, {}).get(
            "allow", ()
        ):
            if _has_matching_deny(roles, policy, rule_action, rule_pattern):
                continue
            lines.add(f"{role}:{rule_action}:{rule_pattern}")
    return sorted(lines)


def perm_batch(requests, policy):
    """Evaluate independent requests and return a mapping of id to bool.

    requests is an iterable of mappings with id, user, action and resource
    keys. Every request is evaluated from scratch with allow, so an expanded
    role set or decision from one request never affects another user. A
    later request carrying a duplicate id overwrites the earlier result.
    """
    # Fix 10: hold no expanded role set or decision between requests. Each
    # request calls allow independently, so users can never inherit another
    # user's roles through reused state.
    results = {}
    for request in requests:
        results[request["id"]] = allow(
            request["user"],
            request["action"],
            request["resource"],
            policy,
        )
    return results
