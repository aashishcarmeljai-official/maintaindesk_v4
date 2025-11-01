# MaintainDesk: A Comprehensive Maintenance Management System

MaintainDesk is a powerful, multi-tenant, and feature-rich Computerized Maintenance Management System (CMMS) built with Flask. It is designed to help organizations of all sizes manage their equipment, inventory, and maintenance workflows efficiently. The system features a sophisticated Role-Based Access Control (RBAC) system, real-time IoT data integration via MQTT, and a public-facing portal for equipment failure reporting.

## Table of Contents

1.  [Core Features](#core-features)
2.  [Technology Stack](#technology-stack)
3.  [Project Structure](#project-structure)
4.  [Setup and Installation](#setup-and-installation)
5.  [Key Workflows](#key-workflows)
6.  [Command-Line Interface (CLI)](#command-line-interface-cli)
7.  [Deployment Considerations](#deployment-considerations)

## Core Features

### 1. Multi-Tenant Architecture
The application is built from the ground up to support multiple independent companies on a single deployment.

*   **Super Admin Portal:** A dedicated interface for a super administrator to onboard and manage client companies.
*   **Data Isolation:** All company data, from users and assets to work orders and settings, is strictly segregated using a `company_id` in the database, ensuring complete privacy and security.
*   **Unique Signup Process:** New companies are provided with a unique email and key combination for their first administrator to sign up, which then creates the company's entire default infrastructure (roles, categories, etc.).

### 2. Advanced Role-Based Access Control (RBAC)
MaintainDesk features a granular and flexible permission system to control user access to every part of the application.

*   **Centralized Permissions:** All possible user actions are defined as permissions in a central `permissions.py` file.
*   **Customizable Roles:** Company administrators can create custom roles (e.g., "HVAC Specialist," "Safety Inspector") and assign a specific set of permissions to each.
*   **Default Roles:** New companies are automatically provisioned with a set of default roles (Admin, Manager, Technician, Viewer) to get started quickly.
*   **Hierarchical Control:** Roles have a `level` attribute, allowing higher-level users (like Managers) to manage users in lower-level roles.

### 3. Comprehensive Asset Management
Track and manage all organizational assets with detailed records and associated media.

*   **Equipment Management:** Maintain a complete registry of all physical equipment. Each record can store technical specifications, manufacturer, model, serial numbers, purchase and warranty dates, and its physical location.
*   **Inventory Management:** Manage spare parts, tools, and consumables. Track current stock levels, set minimum/maximum thresholds to prevent stockouts, and record unit costs.
*   **Media Uploads:** Attach relevant files—images, technical documents, videos, or audio notes—to any equipment, inventory item, vendor, or work order.

### 4. End-to-End Work Order Management
A complete workflow for creating, approving, assigning, and completing maintenance tasks.

*   **Approval Workflow:** Work orders created by users without approval rights are automatically placed in an "On Hold" state. An email notification is sent to designated approvers who can review, approve, or reject the request.
*   **Assignment and Scheduling:** Assign work orders to individual technicians or entire teams. Schedule tasks for specific dates and set due dates to ensure timely completion.
*   **Email Notifications:** The system automatically sends email notifications for key events, such as new work order assignments, status changes (approved/rejected), and new user invitations.

### 5. IoT and Real-Time Monitoring
Integrate with physical sensors and meters to monitor equipment health in real-time.

*   **MQTT Integration:** A standalone MQTT client subscribes to data streams from registered IoT devices.
*   **Live Analytics:** Meter readings are forwarded in real-time via WebSockets to the frontend, allowing for live data visualization on analytics dashboards.
*   **Historical Data Logging:** All incoming meter readings are timestamped and stored in the database, enabling historical analysis, reporting, and trend identification.

### 6. Public Failure Reporting with QR Codes
Streamline the maintenance request process by empowering anyone to report issues.

*   **QR Code Generation:** Generate a unique QR code for any piece of equipment.
*   **Public Reporting Portal:** Scanning the QR code leads to a public, mobile-friendly form where anyone—without needing to log in—can report a failure, describe the issue, and even upload photos.
*   **Automated Request Creation:** Submitted reports automatically generate a work order request in the system, which then enters the standard approval workflow.

### 7. Data Management and Reporting
*   **Backup and Restore:** Administrators can generate a complete JSON backup of all their company's data and restore from it, providing a crucial disaster recovery mechanism.
*   **Data Export:** Reports, such as historical meter readings, can be exported to CSV format for external analysis in tools like Excel.

## Technology Stack

This project leverages a modern and robust stack for web development and real-time communication.

| Component             | Technology                                      | Purpose                                                                |
| --------------------- | ----------------------------------------------- | ---------------------------------------------------------------------- |
| **Backend Framework** | Flask                                           | Core web application framework, routing, and request handling.         |
| **Database**          | PostgreSQL                                      | Primary relational database for data persistence.                      |
| **ORM**               | SQLAlchemy                                      | Database toolkit and Object-Relational Mapper for Python.              |
| **Real-time**         | Flask-SocketIO, python-socketio                 | Enables bidirectional, real-time communication for live dashboards.    |
| **IoT Protocol**      | Paho-MQTT                                       | Client library for connecting to and subscribing from an MQTT broker.  |
| **Authentication**    | Flask-Login, Flask-Bcrypt, itsdangerous         | Handles user sessions, secure password hashing, and token generation.  |
| **Frontend**          | HTML5, CSS3, JavaScript, Jinja2                 | Standard web technologies for the user interface and templating.       |
| **Deployment**        | Gunicorn (recommended)                          | WSGI server for running the Flask application in production.           |
| **Environment Mgmt**  | python-dotenv                                   | Manages environment variables for configuration.                       |
| **Data Handling**     | Pandas                                          | Used for creating and exporting data reports to CSV format.            |

## Project Structure

The project is organized into a modular and maintainable structure that separates concerns.

```
C:.
│   .env                  # Stores environment variables (DB URI, secret keys)
│   app.py                # Main Flask application file: routes, logic, SocketIO events
│   models.py             # SQLAlchemy database models defining the schema
│   mqtt_client.py        # Standalone script that connects to MQTT and forwards data
│   permissions.py        # Central configuration for all roles and permissions
│   requirements.txt      # List of Python dependencies
│
├───static/
│   ├───css/              # Custom CSS stylesheets
│   ├───js/               # Custom JavaScript files
│   └───uploads/          # Directory for user-uploaded media (organized by module)
│
└───templates/
    │   base.html         # The master HTML layout template
    │   index.html        # The main dashboard page
    │   login.html        # User login page
    │   super_admin.html  # Portal for the super administrator
    │
    ├───analytics/        # Templates for data visualization dashboards
    ├───equipment/        # Templates for Equipment CRUD operations, QR codes
    ├───inventory/        # Templates for Inventory CRUD operations
    ├───partials/         # Reusable HTML snippets (_sidebar.html, _modals.html)
    ├───public/           # Public-facing pages (e.g., QR code report form)
    ├───roles/            # Templates for managing user roles and permissions
    ├───signup/           # Multi-step company/user registration templates
    ├───users/            # Templates for user management (add, edit, invite)
    └───work_orders/      # Templates for Work Order management and workflows
```

## Setup and Installation

Follow these steps to get the application running locally for development.

### Prerequisites
*   Python 3.8+
*   PostgreSQL Server
*   An MQTT Broker (e.g., Mosquitto, HiveMQ)

### 1. Clone the Repository
```bash
git clone <repository-url>
cd <repository-directory>
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory and add the following variables.

```
# A strong, random string for session security
SECRET_KEY='your_super_secret_key'

# Connection string for your PostgreSQL database
DATABASE_URI='postgresql://user:password@host:port/database_name'

# Configuration for the email sending service (e.g., Gmail)
MAIL_SERVER='smtp.gmail.com'
MAIL_PORT=465
MAIL_USE_SSL=true
MAIL_USERNAME='your-email@gmail.com'
MAIL_PASSWORD='your-app-password' # Use an App Password for Gmail
MAIL_DEFAULT_SENDER='your-email@gmail.com'

# (Optional) Google Maps API Key for location features
GOOGLE_MAPS_API_KEY='your_google_maps_api_key'
```

### 5. Initialize the Database
This command will create all the necessary tables and seed the database with a default company and an admin user.

```bash
flask init-db
```
This will create a user with the following credentials:
*   **Email:** `admin@example.com`
*   **Password:** `admin123`

### 6. Run the Application
You need to run two separate processes: the Flask web server and the MQTT client.

**Terminal 1: Run the Flask/SocketIO Server**
```bash
python app.py
```
The application will be available at `http://127.0.0.1:8000`.

**Terminal 2: Run the MQTT Client**
```bash
python mqtt_client.py
```
This client will connect to the database to fetch configuration, connect to the MQTT broker, and start forwarding messages to the Flask server.

## Key Workflows

### Onboarding a New Company (Super Admin)

1.  **Login as Super Admin:** The Super Admin logs in using credentials stored in `admin_password.json`.
2.  **Add Company:** From the Super Admin dashboard, the admin adds a new company by providing a Company Name, a primary contact Email, and the number of users allowed.
3.  **Key Generation:** The system saves this information to `o_d.json` and generates a unique, secret key for the new company.
4.  **Share Credentials:** The Super Admin securely shares the primary contact Email and the generated Key with the new company's administrator.

### First User Signup

1.  **Step 1 - Email Verification:** The new company's administrator navigates to the signup page and enters their registered email address. The system validates this against the `o_d.json` file.
2.  **Step 2 - Key Verification:** The user is prompted to enter the unique secret key they received from the Super Admin.
3.  **Step 3 - Account Creation:** Upon successful key verification, the user provides their name, username, and password. When this form is submitted:
    *   A new record is created in the `companies` table.
    *   The `create_default_roles_and_permissions` function is triggered, populating the database with default roles (Admin, Manager, etc.), permissions, categories, and other essential data for the new company.
    *   The user's account is created and assigned the 'Admin' role within their new company.

### Creating and Managing a Work Order

1.  **Creation:** A logged-in user with the `CAN_CREATE_WORK_ORDER` permission creates a new work order, linking it to a piece of equipment and providing details like priority, description, and assignment.
2.  **Approval Check:**
    *   If the user has the `CAN_APPROVE_WORK_ORDER` permission (e.g., a Manager), the work order is automatically approved and its status is set to 'Open'. If it was assigned, the assignee is notified via email.
    *   If the user does not have this permission (e.g., a Technician), the work order's status is set to 'On Hold', and an email is sent to all users with approval rights.
3.  **Review and Approval:** A Manager reviews the 'On Hold' request.
    *   **On Approval:** The status is changed to 'Open', and the creator is notified. If an assignee was set, they are also notified.
    *   **On Rejection:** The Manager must provide a reason. The work order record and any associated files are permanently deleted, and the creator is notified of the rejection and the reason.
4.  **Completion:** The assigned technician performs the work and updates the status to 'Completed', which sets the `completed_at` timestamp.

## Command-Line Interface (CLI)

The application includes custom Flask CLI commands for database management.

*   **`flask init-db`**
    *   Drops all existing tables in the database (destructive).
    *   Recreates all tables based on the `models.py` schema.
    *   Seeds the database with a default company, default roles/permissions, and a default `admin@example.com` user. Essential for initial setup and development resets.

*   **`flask delete-db`**
    *   A simple, destructive command that drops all tables from the database.

*   **`flask cleanup-logs`**
    *   A maintenance command designed to be run periodically (e.g., via a cron job).
    *   It deletes notification logs that have passed their retention period, specifically targeting sensitive logs (like generated passwords) for immediate cleanup.

## Deployment Considerations

*   **WSGI Server:** Do not use the Flask development server (`python app.py`) in production. Use a production-ready WSGI server like **Gunicorn** or **uWSGI**.
*   **Eventlet/Gevent:** Because the application uses Flask-SocketIO, the WSGI server must be run with Eventlet or Gevent worker types to handle the WebSocket connections correctly.
    *   Example Gunicorn command:
        ```bash
        gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:8000 app:app
        ```
*   **Reverse Proxy:** Place the Gunicorn server behind a reverse proxy like **Nginx** or **Apache**. The reverse proxy will handle incoming HTTP requests, manage SSL/TLS termination, and serve static files efficiently.
*   **Running the MQTT Client:** The `mqtt_client.py` script must be run as a persistent background service. Use a process manager like **systemd** or **Supervisor** to ensure it runs continuously and restarts automatically if it fails.
*   **Environment Variables:** In a production environment, never commit the `.env` file. Use the deployment platform's system for managing environment variables securely.