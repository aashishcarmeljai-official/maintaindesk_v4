# A centralized file for defining all permissions and default role configurations.

# --- 1. DEFINE ALL PERMISSION NAMES ---
# Using a set is efficient for checking existence and preventing duplicates.
PERMISSION_NAMES = {
    # --- General Permissions ---
    'CAN_VIEW_DASHBOARD',

    # --- User & Access Management (Sidebar Access) ---
    'CAN_MANAGE_USERS',         # View user list, invite, add
    'CAN_MANAGE_ROLES',         # View/edit roles page
    'CAN_MANAGE_TEAMS',         # View/edit teams page

    # --- Work Order Permissions ---
    'CAN_CREATE_WORK_ORDER',      # Allows creating a WO (might go into 'On Hold')
    'CAN_EDIT_WORK_ORDER',        # Allows editing a WO (may trigger re-approval)
    'CAN_DELETE_WORK_ORDER',      # Allows deleting a WO
    'CAN_APPROVE_WORK_ORDER',     # Allows approving/rejecting WOs, auto-approves own
    'CAN_MANAGE_ALL_WORK_ORDERS', # Sees all WOs, bypasses creator/assignee checks

    # --- Asset Management (Sidebar Access) ---
    'CAN_MANAGE_ASSETS',          # Main permission to see the 'Assets' dropdown
    'CAN_MANAGE_EQUIPMENT',       # To see the 'Equipment' link
    'CAN_MANAGE_INVENTORY',       # To see the 'Inventory' link

    # --- Granular Equipment Permissions ---
    'CAN_VIEW_EQUIPMENT',
    'CAN_ADD_EQUIPMENT',
    'CAN_EDIT_EQUIPMENT',
    'CAN_DELETE_EQUIPMENT',

    # --- Granular Inventory Permissions ---
    'CAN_VIEW_INVENTORY',
    'CAN_ADD_INVENTORY',
    'CAN_EDIT_INVENTORY',
    'CAN_DELETE_INVENTORY',

    # --- Vendor Management ---
    'CAN_MANAGE_VENDORS',         # For sidebar visibility
    'CAN_VIEW_VENDORS',
    'CAN_ADD_VENDORS',
    'CAN_EDIT_VENDORS',
    'CAN_DELETE_VENDORS',

    # --- Company Settings & Data ---
    'CAN_MANAGE_CATEGORIES',
    'CAN_MANAGE_DEPARTMENTS',
    'CAN_MANAGE_LOCATIONS',
    'CAN_MANAGE_UNITS',
    'CAN_MANAGE_CURRENCIES',

    # --- System & Reporting ---
    'CAN_VIEW_REPORTS',
    'CAN_MANAGE_SETTINGS',
    'CAN_SEND_BROADCASTS',
}


# --- 2. DEFINE DEFAULT ROLE CONFIGURATIONS ---
# This dictionary maps role names to their descriptions, levels, and permissions.
ROLES_CONFIG = {
    'Admin': {
        'desc': 'Full access to all system features.',
        'is_admin': True,
        'level': 0,
        'perms': list(PERMISSION_NAMES) # Admins get all defined permissions
    },
    'Manager': {
        'desc': 'Can manage day-to-day operations, users, and assets.',
        'is_admin': False,
        'level': 10,
        'perms': [
            'CAN_VIEW_DASHBOARD',
            'CAN_MANAGE_USERS', 'CAN_MANAGE_ROLES', 'CAN_MANAGE_TEAMS',
            'CAN_CREATE_WORK_ORDER', 'CAN_EDIT_WORK_ORDER', 'CAN_DELETE_WORK_ORDER',
            'CAN_APPROVE_WORK_ORDER', 'CAN_MANAGE_ALL_WORK_ORDERS',
            'CAN_MANAGE_ASSETS', 'CAN_MANAGE_EQUIPMENT', 'CAN_MANAGE_INVENTORY',
            'CAN_VIEW_EQUIPMENT', 'CAN_ADD_EQUIPMENT', 'CAN_EDIT_EQUIPMENT', 'CAN_DELETE_EQUIPMENT',
            'CAN_VIEW_INVENTORY', 'CAN_ADD_INVENTORY', 'CAN_EDIT_INVENTORY', 'CAN_DELETE_INVENTORY',
            'CAN_MANAGE_VENDORS', 'CAN_VIEW_VENDORS', 'CAN_ADD_VENDORS', 'CAN_EDIT_VENDORS', 'CAN_DELETE_VENDORS',
            'CAN_MANAGE_CATEGORIES', 'CAN_MANAGE_DEPARTMENTS', 'CAN_MANAGE_LOCATIONS',
            'CAN_MANAGE_UNITS', 'CAN_MANAGE_CURRENCIES',
            'CAN_VIEW_REPORTS', 'CAN_MANAGE_SETTINGS', 'CAN_SEND_BROADCASTS',
        ]
    },
    'Technician': {
        'desc': 'Can create work orders and view assigned assets.',
        'is_admin': False,
        'level': 20,
        'perms': [
            'CAN_VIEW_DASHBOARD',
            'CAN_CREATE_WORK_ORDER',
            'CAN_EDIT_WORK_ORDER', # Can edit their own WOs (triggers re-approval)
            'CAN_VIEW_EQUIPMENT',
            'CAN_VIEW_INVENTORY',
            'CAN_VIEW_VENDORS',
        ]
    },
    'Viewer': {
        'desc': 'Read-only access and can submit work order requests.',
        'is_admin': False,
        'level': 30,
        'perms': [
            'CAN_VIEW_DASHBOARD',
            'CAN_CREATE_WORK_ORDER',
            'CAN_VIEW_REPORTS',
        ]
    }
}