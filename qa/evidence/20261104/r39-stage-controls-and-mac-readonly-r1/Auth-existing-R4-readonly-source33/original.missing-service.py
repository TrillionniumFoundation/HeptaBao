def missing_service(code, out, err):
    if code not in (3, 113) or out:
        return False
    try:
        lines = err.decode('utf-8', 'strict').strip().splitlines()
    except UnicodeError:
        return False
    exact = 'Could not find service "' + LABEL + '" in domain for user gui: 501'
    return lines == [exact] or lines == ['Bad request.', exact]

