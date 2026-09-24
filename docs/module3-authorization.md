\# Module 3 — Authorization Design



\## 1. Objective



The objective of this module is to implement a least-privilege authorization model for the SecureHealth API using API scopes and Python-based authorization checks.



The design does not depend on Auth0 Core RBAC.



The API validates the JWT and checks whether the required scope is present before allowing access.



\---



\## 2. Authorization Model



The authorization flow is:



User

↓

Auth0

↓

JWT Access Token

↓

SecureHealth API

↓

JWT Validation

↓

Scope Validation

↓

ALLOW / 403 FORBIDDEN



The JWT is validated for:



\- Signature

\- Issuer

\- Audience

\- Expiry



After successful token validation, the API checks the required scope.



\---



\## 3. Permission Model



\### HR



Permissions:



\- read:employees

\- update:employees



HR can read and update employee information but cannot access financial transactions, systems, or IAM access management.



\### Finance



Permission:



\- read:transactions



Finance can read financial transaction information but cannot access employee, system, or IAM access management functions.



\### IT



Permissions:



\- read:systems

\- update:systems



IT can read and update system information but does not automatically receive HR or Finance permissions.



\### Sales



Permission:



\- read:reports



Sales can read business reports but does not receive access to employee, financial, or system information.



\### IAM Admin



Permissions:



\- read:users

\- manage:access



IAM Admin can read IAM user information and manage access permissions.



\---



\## 4. Least Privilege



Least privilege means giving a user only the permissions required to perform their job.



For example, an HR user requires:



\- read:employees

\- update:employees



The HR user does not require:



\- read:transactions

\- update:systems

\- manage:access



Therefore, those permissions are not granted.



This reduces the potential impact of a compromised account and limits unauthorized access to business resources.



\---



\## 5. Separation of Duties



The authorization model separates responsibilities between departments.



| User Type | Responsibility |

|---|---|

| HR | Employee information |

| Finance | Financial transactions |

| IT | Systems |

| Sales | Business reports |

| IAM Admin | Identity and access management |



A user performing HR functions does not automatically receive IAM administration privileges.



For example:



HR

→ Employee management



IAM Admin

→ Access management



This separation helps prevent one user from having unnecessary control over unrelated business functions.



\---



\## 6. ALLOW and DENY Decisions



The API follows this model:



Valid JWT

\+

Required scope

=

ALLOW



Valid JWT

\+

Missing required scope

=

403 FORBIDDEN



Invalid or expired JWT

=

401 UNAUTHORIZED



Examples:



HR → read:employees → ALLOW



Finance → read:employees → DENY



Finance → read:transactions → ALLOW



HR → read:transactions → DENY



IT → update:systems → ALLOW



Sales → read:systems → DENY



\---



\## 7. Security Benefits



This authorization model provides:



\- Least privilege

\- Separation of duties

\- Explicit permission boundaries

\- Reduced unauthorized access

\- Clear 401 and 403 handling

\- API-level authorization enforcement

\- Auditable permission mapping



\---



\## 8. Module 3 Deliverables



The completed module contains:



\- Permission matrix

\- Custom Auth0 API

\- API scopes

\- JWT validation module

\- Python authorization module

\- Positive and negative authorization tests

\- Least privilege documentation

\- Separation of duties documentation

