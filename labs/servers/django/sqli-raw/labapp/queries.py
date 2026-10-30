"""
Raw SQL builders for the sqli-raw lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.

This module is deliberately kept free of any Django request/DB-execution
code so that the vulnerable string-building logic can be unit tested with a
pure string assertion, with no live database required (see
labapp/tests.py::QueriesUnitTests).
"""


def build_search_query(username: str) -> str:
    """Build the raw SQL used to look a user up by username and return the
    row (id, username, role) that labapp/views.py::search_view treats as
    the account the caller authenticated/searched as.
    """
    # INTENTIONALLY VULNERABLE: unparameterized raw SQL, do not copy this
    # pattern. The correct, safe way to do this with Django's .raw() is:
    #
    #     UserProfile.objects.raw(
    #         "SELECT labapp_userprofile.id, auth_user.username, "
    #         "labapp_userprofile.role "
    #         "FROM labapp_userprofile "
    #         "INNER JOIN auth_user ON auth_user.id = labapp_userprofile.user_id "
    #         "WHERE auth_user.username = %s",
    #         [username],
    #     )
    #
    # Here we instead splice `username` directly into the SQL text with an
    # f-string, so any single quote or SQL keyword the caller supplies is
    # interpreted as SQL rather than data. For example, calling this with
    #
    #     admin' --
    #
    # closes the string literal early and comments out the rest of the
    # query, and a UNION SELECT payload can be used to smuggle arbitrary
    # rows (including a forged role='admin' column) into the result set
    # consumed by labapp/views.py::search_view, e.g.:
    #
    #     nobody' UNION SELECT au.id, au.username, 'admin'
    #     FROM auth_user au WHERE au.username='moderator1' --
    query = (
        "SELECT labapp_userprofile.id, auth_user.username, "
        "labapp_userprofile.role "
        "FROM labapp_userprofile "
        "INNER JOIN auth_user ON auth_user.id = labapp_userprofile.user_id "
        f"WHERE auth_user.username = '{username}'"
    )
    return query
