from api.auth import validate_token, has_scope


def authorize_request(token, required_scope, **kwargs):
    """
    Validate JWT and check whether the caller has the required scope.

    Returns:
        (True, payload)  -> authorized
        (False, message) -> denied
    """

    try:
        payload = validate_token(token, **kwargs)

    except Exception as e:
        return False, f"401 Unauthorized: {e}"

    if not has_scope(payload, required_scope):
        return False, f"403 Forbidden: missing scope '{required_scope}'"

    return True, payload