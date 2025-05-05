**Document Management System (DMS)**

**For: E-Parliament Project**

**Prepared by: Md. Al-Amin Hossain**

**Date: 05 May, 2025**

**1. Introduction**

**1.1 Purpose**

The purpose of this document is to define the software requirements for
the Document Management System (DMS) module of the E-Parliament system.
The DMS will enable efficient and secure management of categorized
parliamentary documents, with collaboration features including sharing,
grouping, commenting, and downloading.

**1.2 Scope**

This system is a submodule of the E-Parliament platform and will:

-   Allow consultants, officials, and committee members to upload,
    manage, and access categorized documents.

-   Support team/group-based document access control.

-   Enable cross-team sharing and collaboration.

-   Provide comment and version control features.

-   Ensure document-level permission and audit trails.

**2. Overall Description**

**2.1 Product Perspective**

This system is part of the larger E-Parliament platform. It will be
developed as a standalone Django app and integrated via REST APIs or
internal app configuration with other modules like Member Management,
Meeting Management, and Reporting.

**2.2 Users and Roles**

-   **Admin (Parliament Secretariat IT)**

-   **Consultant**

-   **Parliament Official**

-   **Committee Member**

-   **Team Leader (of a group)**

-   **Team Member**

**2.3 Assumptions and Dependencies**

-   System runs on a secure Django backend with MySQL/PostgreSQL DB.

-   User authentication and role management will use Django's built-in
    auth or a centralized user service.

-   Document storage may be local or cloud-based (S3/MinIO recommended).

-   All communication will be HTTPS secured.

**3. Functional Requirements**

**3.1 Document Management**

-   FR1.1: Users can upload documents with metadata (title, category,
    tags, description).

-   FR1.2: Documents can be versioned (auto-track or manual).

-   FR1.3: Each document must belong to one or more categories.

-   FR1.4: Users can search and filter documents by category, tag, date,
    and uploader.

**3.2 Group/Team Management**

-   FR2.1: Admins and team leaders can create/edit/delete teams.

-   FR2.2: Users can be assigned to multiple teams.

-   FR2.3: Each team has specific permissions on documents (Read, Write,
    Comment, Share).

**3.3 Sharing and Access Control**

-   FR3.1: A team can share documents with another team or specific
    users.

-   FR3.2: Shared documents retain permission sets (Read, Comment only,
    or Full Access).

-   FR3.3: Only document owners or admins can revoke access.

**3.4 Commenting and Collaboration**

-   FR4.1: Users with access can comment on a document.

-   FR4.2: Comment threads must support replies and edit/delete (based
    on permissions).

-   FR4.3: Notification is sent when someone comments on a document.

**3.5 Downloading and Viewing**

-   FR5.1: Users can download documents based on their permission.

-   FR5.2: Preview supported for common formats (PDF, DOCX, images).

-   FR5.3: Logs are kept for every download and view event.

**3.6 Audit and Activity Logs**

-   FR6.1: Maintain audit trail for document uploads, shares, edits,
    downloads.

-   FR6.2: Activity logs viewable by Admin and Team Leaders.

**4. Non-Functional Requirements**

**4.1 Security**

-   Secure document access via permission control.

-   All files stored with encryption at rest and in transit.

-   Role-based access enforced.

**4.2 Performance**

-   Must support at least 100 concurrent users.

-   Large file uploads (up to 500MB) supported with chunked uploads.

**4.3 Usability**

-   Responsive, clean interface with file tree navigation and team
    dashboards.

**4.4 Scalability**

-   Scalable design using Django apps and REST APIs.

-   Option to shift file storage to object storage like AWS S3/MinIO.

**5. Data Models (High-Level)**

**User**

-   id, name, email, role, assigned_teams

**Team**

-   id, name, members \[M2M User\]

**Document**

-   id, title, file, version, category, tags, owner, upload_date,
    visibility

**DocumentPermission**

-   document_id, user/team_id, permission_type (Read, Write, Comment,
    Share)

**Comment**

-   id, document_id, user_id, parent_comment, text, created_at

**AuditLog**

-   id, user_id, action_type, target_object, timestamp
