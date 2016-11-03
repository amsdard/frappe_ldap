import ldap
import frappe
import itertools
from frappe_ldap.templates.pages.ldap_login import get_ldap_settings
from frappe_ldap.templates.pages.ldap_login import get_bound_connection


def sync_ldap_projects():
    server_details = get_ldap_settings()
    conn = get_bound_connection(server_details)

    projects = get_ldap_projects(conn, server_details)
    existing = get_existing_projects()
    new_projects = list(set(projects) - set(existing))

    for project in new_projects:
        d = frappe.new_doc("Project")
        d.owner = "Administrator"
        d.project_name = project

        d.insert(ignore_permissions=True)


def get_ldap_projects(conn, server_details):
    projects = []

    project_filter = server_details.get('project_filter', '(objectClass=posixGroup)')
    base_dn = server_details.get('base_dn')

    try:
        # search for erpnext users in ldap database
        result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, project_filter)
    except ldap.LDAPError as e:
        frappe.msgprint(e.message, raise_exception=1)
        conn.unbind_s()
        raise

    for dn, r in result:
        projects.append(str(r['cn'][0]))

    return projects


def get_existing_projects():
    projects = frappe.db.sql("SELECT name FROM tabProject")
    return list(itertools.chain(*projects))
