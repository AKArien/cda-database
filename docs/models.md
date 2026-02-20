# Merise schemas

Note : this document contains diagrams declared in the mermaid js format and is reccomended to be visualised with a compatible tool.

## MCD (Conceptual Data Model)

```mermaid
erDiagram
    "Roles (internal to postgres)" || --o{ Access : "0,n
        has role
        1,1
    "
    "Access group" ||--o{ Access : "0,n
        is in
        0,n
    "
    "Access group" ||--o{ Permission : "0,n
        has permissions
        0,n
    "
    Access ||--o{ Permission : "0,n
        has permissions
        0,n
    "
    Permission ||--o{ Site : "0,n
        controls
        0,n
    "
    Permission ||--o{ Gateway : "0,n
        controls
        0,n
    "
    Permission ||--o{ Watcher : "0,n
        controls
        0,n
    "
    Site ||--|{ Gateway : "1,n
        contains
        1,1
    "
    Gateway ||--o{ Watcher : "1,n
        handles
        1,1
    "
    Watcher ||--o{ Report : "0,n
        creates
        1,1
    "
    "Access group" {
        string description
    }
    Access {
        string name
        string pass
        string administration_notes
        timestamp expiration_date
        int session_limit_time
        bool must_change_pass
    }
    Site {
        string name
        string info
        path perimeter
    }
    Gateway {
        string name
        string info
        point location
    }
    Watcher {
        string name
        string info
        pont location
    }
    Report {
        timestamp moment
        int difference
    }
```

## MLD (Logical Data Model)

```mermaid
erDiagram
    Sites ||--o{ Gateways : "site -> Sites.id"
    Gateways ||--o{ Watchers : "gateway -> Gateways.id"
    Watchers ||--o{ Reports : "watcher -> Watchers.id"

    Accesses ||--o{ Permissions : "granted by -> Accesses.id"
    Accesses ||--o{ "Access in group" : "access -> Accesses.id"
    "Acceses groups" ||--o{ "Access in group" : "a_group -> Accesses groups.id"

    %% permissions can target several entity types; modelled here as optional relationships
    Accesses ||--o{ Permissions : target_access
    "Acceses groups" ||--o{ Permissions : target_group
    Sites ||--o{ Permissions : target_site
    Gateways ||--o{ Permissions : target_gateway
    Watchers ||--o{ Permissions : target_watcher

    Sites {
        int id PK
        text name
        text info
        path perimeter
    }

    Gateways {
        int id PK
        int site FK
        text name
        text info
        point location
    }

    Watchers {
        int id PK
        int gateway FK
        text name
        text info
        point location
    }

    Reports {
        timestamp moment PK
        int watcher PK, FK
        int report
    }

    Accesses {
        int id PK
        text name UK
        text admin_notes
        text pass
        timestamp expires
        name role
        int max_session_time
        bool force_change_pass
    }

    "Acceses groups" {
        int id PK
        text name UK
        text description
    }

    "Access in group" {
        int access PK, FK
        int a_group PK, FK
    }

    Permissions {
        int granted_by FK
        int reciever PK
        permissions_owner reciever_type PK
        permissions_verb action PK
        bool propagate
        permissions_members member PK
        int target PK
        permissions_target target_type PK
    }
```

## MPD (Physical Data Model)

```mermaid
erDiagram
    sites ||--o{ gateways : site
    gateways ||--o{ watchers : gateway
    watchers ||--o{ reports : watcher

    auth_accesses ||--o{ permissions : granted_by

    auth_accesses ||--o{ access_in_group : access
    accesses_group ||--o{ access_in_group : a_group

    %% polymorphic target/receiver: enforced by trigger check_permissions_validity + app/RLS, not real FKs
    sites ||--o{ permissions : "target (when target_type=site)"
    gateways ||--o{ permissions : "target (when target_type=gateway)"
    watchers ||--o{ permissions : "target (when target_type=watcher)"
    auth_accesses ||--o{ permissions : "target/receiver (when type=access)"
    accesses_group ||--o{ permissions : "target/receiver (when type=a_group)"

    sites {
        serial id PK
        text name "NOT NULL"
        text info
        path perimeter
    }

    gateways {
        serial id PK
        int site FK "references sites(id)"
        text name "NOT NULL"
        text info
        point location
    }

    watchers {
        serial id PK
        int gateway FK "references gateways(id)"
        text name "NOT NULL"
        text info
        point location "NOT NULL"
    }

    reports {
        timestamp moment PK
        int watcher PK, FK "references watchers(id)"
        int report
        %% TimescaleDB: hypertable partition_column=moment segmentby=watcher
    }

    auth_accesses {
        serial id PK
        text name UK
        text admin_notes
        text pass "NOT NULL (len<512) + encrypted by trigger"
        timestamp expires
        name role "NOT NULL (len<512) + must exist in pg_roles (constraint trigger)"
        int max_session_time
        bool force_change_pass
    }

    accesses_group {
        serial id PK
        text name UK "NOT NULL"
        text description
    }

    access_in_group {
        int access PK, FK "references auth.accesses(id)"
        int a_group PK, FK "BUG: currently references auth.accesses(id) in migration; should reference accesses_group(id)"
    }

    permissions {
        int granted_by FK "references auth.accesses(id)"
        int reciever PK
        permissions_owner reciever_type PK
        permissions_verb action PK
        bool propagate
        permissions_members member PK
        int target PK
        permissions_target target_type PK
        %% validity enforced by trigger check_permissions_validity()
    }
```