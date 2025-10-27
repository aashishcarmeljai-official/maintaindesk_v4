import os
import io
import csv
import pint
import json
import uuid
import qrcode
import base64
import random
import string
from flask_mail import Mail, Message
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, redirect, url_for, request, session, abort, jsonify, Response
from flask import flash as flask_flash, g
from flask_session import Session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, user_logged_in
from flask_socketio import SocketIO, emit, join_room, leave_room
from models import db, bcrypt, User, Company, Role, Location, Permission, Category, Department, Equipment, Unit, Currency, InventoryItem, Vendor, VendorContact, Team, team_members, NotificationLog, WorkOrder, MqttConfig, Meter
from sqlalchemy import func, cast, text, case
import pycountry
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.orm import joinedload, aliased, undefer
from werkzeug.utils import secure_filename
from sqlalchemy.dialects.postgresql import JSONB
from permissions import PERMISSION_NAMES, ROLES_CONFIG

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# --- MAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'false').lower() in ['true', '1']
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'true').lower() in ['true', '1']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# --- SOCKETIO INITIALIZATION ---
# We use 'threading' for the dev server and will switch to eventlet for production.
socketio = SocketIO(app, async_mode='threading')

ADMIN_PASS_FILE = os.path.join(app.root_path, 'admin_password.json')
ORG_DATA_FILE = os.path.join(app.root_path, 'o_d.json')

db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

ALLOWED_EXTENSIONS = {
    'images': {'png', 'jpg', 'jpeg', 'gif'},
    'videos': {'mp4', 'mov', 'avi', 'mkv', 'webm'},
    'audio': {'mp3', 'wav', 'ogg', 'webm'},
    'documents': {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'}
}

def allowed_file(filename, file_type):
    """Checks if a file's extension is allowed for a given type."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

def process_uploads(instance, form_files, model_name):
    """
    Generic function to prepare file-saving operations.
    - instance: The SQLAlchemy model instance (e.g., an Equipment or InventoryItem object).
    - form_files: The request.files object from the form.
    - model_name: A string like 'equipment' or 'inventory' to determine the save directory.
    """
    saved_files = {'images': [], 'videos': [], 'audio_files': [], 'documents': []}
    save_actions = []
    
    type_map = [
        ('images', 'images', 'images'), 
        ('videos', 'videos', 'videos'), 
        ('audio_files', 'audio', 'audio_files'), 
        ('documents', 'documents', 'documents')
    ]
    
    for key, folder, input_name in type_map:
        uploaded_files = form_files.getlist(input_name)
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], model_name, folder)
        os.makedirs(upload_folder, exist_ok=True)
        
        for file in uploaded_files:
            if file and allowed_file(file.filename, folder):
                filename = secure_filename(f"{instance.id}_{folder}_{uuid.uuid4().hex[:8]}_{file.filename}")
                save_path = os.path.join(upload_folder, filename)
                save_actions.append((file, save_path))
                saved_files[key].append(filename)
            elif file:
                flash(f"File type not allowed for: {file.filename}", 'warning')

    return saved_files, save_actions

def delete_all_uploads(instance, model_name):
    """Generic function to delete all media files for a model instance."""
    folder_map = {
        'images': 'images', 'videos': 'videos', 'audio_files': 'audio', 'documents': 'documents'
    }
    for key, folder in folder_map.items():
        filenames = getattr(instance, key)
        if filenames:
            for filename in filenames:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], model_name, folder, filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        print(f"Error deleting file {file_path}: {e}")

def load_json_data(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} if 'password' in filepath else []

def save_json_data(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def create_default_roles_and_permissions(company_id):
    all_permissions = []
    for name in PERMISSION_NAMES:
        perm = Permission.query.filter_by(name=name).first()
        if not perm:
            perm = Permission(name=name)
            db.session.add(perm)
        all_permissions.append(perm)
    db.session.commit()

    for name, config in ROLES_CONFIG.items():
        role = Role(
            company_id=company_id,
            name=name,
            description=config['desc'],
            is_admin=config['is_admin'],
            level=config['level']
        )
        # Assign the correct permission objects based on the names in the config
        role.permissions = [p for p in all_permissions if p.name in config['perms']]
        db.session.add(role)
    
    default_equipment = [
        "Computers", "Electrical", "Furniture", "HVAC", "Machinery",
        "Plumbing", "Tools", "Vehicles"
    ]
    default_inventory = [
        "Bearings", "Belts", "Electrical", "Fasteners", "Filters",
        "Lubricants", "Motors", "Pipes", "Safety", "Sensors", "Tools", "Valves"
    ]

    for cat_name in default_equipment:
        category = Category(
            company_id=company_id,
            name=cat_name,
            category_type='Equipment',
            color='#3f8efc',  # Default Blue
            is_active=True
        )
        db.session.add(category)

    for cat_name in default_inventory:
        category = Category(
            company_id=company_id,
            name=cat_name,
            category_type='Inventory',
            color='#198754',  # Default Green
            is_active=True
        )
        db.session.add(category)
    default_departments = ["Maintenance", "Management", "Production", "Quality"]
    for dept_name in default_departments:
        department = Department(
            company_id=company_id,
            name=dept_name,
            is_active=True
        )
        db.session.add(department)
        
    ureg = pint.UnitRegistry()
    default_units_map = {
        # Base Units
        'meter': {'symbol': 'm'}, 'gram': {'symbol': 'g'}, 'second': {'symbol': 's'},
        'ampere': {'symbol': 'A'}, 'kelvin': {'symbol': 'K'}, 'mole': {'symbol': 'mol'},
        'candela': {'symbol': 'cd'}, 'liter': {'symbol': 'L'}, 'volt': {'symbol': 'V'},
        'watt': {'symbol': 'W'}, 'hertz': {'symbol': 'Hz'}, 'pascal': {'symbol': 'Pa'},
        'each': {'symbol': 'ea'}, 'piece': {'symbol': 'pc'},
        # Derived Units
        'kilometer': {'base': 'meter', 'factor': 1000},
        'centimeter': {'base': 'meter', 'factor': 0.01},
        'millimeter': {'base': 'meter', 'factor': 0.001},
        'kilogram': {'base': 'gram', 'factor': 1000},
        'milligram': {'base': 'gram', 'factor': 0.001},
        'minute': {'base': 'second', 'factor': 60},
        'hour': {'base': 'second', 'factor': 3600},
        'milliliter': {'base': 'liter', 'factor': 0.001},
        'kilovolt': {'base': 'volt', 'factor': 1000},
        'kilowatt': {'base': 'watt', 'factor': 1000},
        'megahertz': {'base': 'hertz', 'factor': 1_000_000},
        'kilopascal': {'base': 'pascal', 'factor': 1000},
    }
    
    base_units_in_db = {}
    for name, data in default_units_map.items():
        if 'base' not in data:
            unit = Unit(company_id=company_id, name=name.capitalize(), symbol=data.get('symbol'))
            db.session.add(unit)
            base_units_in_db[name] = unit
    db.session.flush() # Flush to get IDs for base units

    for name, data in default_units_map.items():
        if 'base' in data:
            base_unit = base_units_in_db.get(data['base'])
            if base_unit:
                unit = Unit(
                    company_id=company_id,
                    name=name.capitalize(),
                    symbol=str(ureg(name).units),
                    base_unit_id=base_unit.id,
                    conversion_factor=data['factor']
                )
                db.session.add(unit)
    
    default_currencies = {
        'USD': {'name': 'United States Dollar', 'symbol': '$'},
        'EUR': {'name': 'Euro', 'symbol': '€'},
        'JPY': {'name': 'Japanese Yen', 'symbol': '¥'},
        'GBP': {'name': 'British Pound', 'symbol': '£'},
        'INR': {'name': 'Indian Rupee', 'symbol': '₹'}, # Added Indian Rupee
        'AUD': {'name': 'Australian Dollar', 'symbol': '$'},
        'CAD': {'name': 'Canadian Dollar', 'symbol': '$'},
        'CHF': {'name': 'Swiss Franc', 'symbol': 'Fr'},
        'CNY': {'name': 'Chinese Yuan', 'symbol': '¥'},
    }
    
    for code, data in default_currencies.items():
        new_curr = Currency(
            company_id=company_id,
            name=data['name'],
            code=code,
            symbol=data['symbol']
        )
        db.session.add(new_curr)
        
    # Create a generic "System Reporter" user for this company
    system_reporter = User(
        company_id=company_id,
        username=f"system_reporter_{company_id}",
        email=f"system_reporter_{company_id}@internal.maintaindesk.com",
        first_name="System",
        last_name="Reporter",
        is_active=False # This account cannot be logged into
    )
    system_reporter.set_password(uuid.uuid4().hex) # Set a secure, random, unknown password
    db.session.add(system_reporter)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@user_logged_in.connect_via(app)
def on_user_logged_in(sender, user):
    """
    Signal listener that runs every time a user successfully logs in.
    Updates the `last_login` timestamp for the user.
    """
    try:
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
    except Exception as e:
        # In case of a database issue, roll back and log the error
        db.session.rollback()
        print(f"Error updating last_login for user {user.id}: {e}")

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_super_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            
            if current_user.role and current_user.role.is_admin:
                return f(*args, **kwargs)

            user_permissions = [p.name for p in current_user.role.permissions] if current_user.role else []
            if permission not in user_permissions:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if session.get('is_super_admin'):
        return redirect(url_for('super_admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        admin_data = load_json_data(ADMIN_PASS_FILE)
        if admin_data and email in admin_data:
            hashed_password = admin_data[email]
            if bcrypt.check_password_hash(hashed_password, password):
                session['is_super_admin'] = True
                flash('Super Admin login successful!', 'success')
                return redirect(url_for('super_admin_dashboard'))
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            remember = True if request.form.get('remember') else False
            login_user(user, remember=remember)
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('login.html', hide_sidebar=True)

@app.route('/logout')
def logout():
    logout_user()
    session.pop('is_super_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup_step1_email():
    session.pop('signup_data', None)
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        org_data = load_json_data(ORG_DATA_FILE)
        company_info = next((org for org in org_data if org['email'].lower() == email.lower()), None)

        if not company_info:
            flash('This email is not registered for signup. Please contact your administrator.', 'danger')
            return redirect(url_for('login'))
        
        session['signup_data'] = company_info
        return redirect(url_for('signup_step2_key'))
    return render_template('signup/step1_email.html', hide_sidebar=True)

@app.route('/signup/verify-key', methods=['GET', 'POST'])
def signup_step2_key():
    signup_data = session.get('signup_data')
    if not signup_data or 'email' not in signup_data:
        return redirect(url_for('signup_step1_email'))

    if request.method == 'POST':
        provided_key = request.form.get('key', '').strip()
        if provided_key == signup_data.get('key'):
            session['signup_data']['key_verified'] = True
            session.modified = True
            return redirect(url_for('signup_step3_details'))
        else:
            flash('The verification key is incorrect. Please try again.', 'danger')
    
    return render_template('signup/step2_key.html', email=signup_data['email'], hide_sidebar=True)

@app.route('/signup/complete', methods=['GET', 'POST'])
def signup_step3_details():
    """Step 3: User enters details and the account is created."""
    signup_data = session.get('signup_data')

    # Protect route: ensure user came from step 2 (email and key verified)
    if not signup_data or not signup_data.get('key_verified'):
        flash('Please complete the previous signup steps first.', 'info')
        return redirect(url_for('signup_step1_email'))

    if request.method == 'POST':
        # --- 1. Data Collection and Validation ---
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, first_name, last_name, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('signup/step3_details.html', data=signup_data, hide_sidebar=True)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup/step3_details.html', data=signup_data, hide_sidebar=True)

        # Check for uniqueness of username and email in the DB
        if User.query.filter_by(username=username).first():
            flash('That username is already taken. Please choose another.', 'warning')
            return render_template('signup/step3_details.html', data=signup_data, hide_sidebar=True)
        if User.query.filter_by(email=signup_data['email']).first():
            flash('An account with this email already exists.', 'warning')
            return redirect(url_for('login'))

        # --- 2. Company and User Limit Check ---
        company = Company.query.filter_by(name=signup_data['company_name']).first()
        if not company:
            # First user from this company is signing up, so create the company record
            company = Company(
                name=signup_data['company_name'],
                user_limit=signup_data['users_allowed']
            )
            db.session.add(company)
            db.session.flush() # Flush to get the new company.id before creating defaults
            create_default_roles_and_permissions(company.id)
        else:
            # Company exists, check if user limit has been reached
            user_count = User.query.filter_by(company_id=company.id).count()
            if user_count >= company.user_limit:
                flash('The maximum number of users for your organization has been reached. Please contact your administrator.', 'danger')
                return redirect(url_for('login'))

        # --- 3. Find Default Role and Department for the new Admin ---
        admin_role = Role.query.filter_by(company_id=company.id, name='Admin').first()
        management_dept = Department.query.filter_by(company_id=company.id, name='Management').first()

        if not admin_role or not management_dept:
            flash('A critical error occurred while setting up the company. Default role or department not found.', 'danger')
            return redirect(url_for('login'))

        # --- 4. Create the new User ---
        new_user = User(
            company_id=company.id,
            role_id=admin_role.id,
            department_id=management_dept.id,
            username=username,
            email=signup_data['email'],
            first_name=first_name,
            last_name=last_name
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # --- 5. Finalize ---
        session.pop('signup_data', None) # Clean up session data
        flash('Your account has been created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    # For a GET request, just show the form
    return render_template('signup/step3_details.html', data=signup_data, hide_sidebar=True)

@app.route('/')
@login_required
@permission_required('CAN_VIEW_DASHBOARD')
def index():
    company_id = current_user.company_id
    
    # --- 1. STATS FOR CARDS ---
    total_equipment = Equipment.query.filter_by(company_id=company_id).count()
    # Placeholder for a more complex "operational" status later
    operational_equipment = total_equipment 
    
    low_stock_items = InventoryItem.query.filter(
        InventoryItem.company_id == company_id,
        InventoryItem.current_stock <= InventoryItem.minimum_stock
    ).count()

    # --- 2. WORK ORDER STATS & LIST (Permission-based) ---
    can_manage_all = current_user.role.is_admin or 'CAN_MANAGE_ALL_WORK_ORDERS' in [p.name for p in current_user.role.permissions]
    
    # Base query for all work orders in the user's company
    wo_query = WorkOrder.query.filter(WorkOrder.company_id == company_id)

    # If the user is NOT a manager/admin, filter to only their relevant WOs
    if not can_manage_all:
        user_team_ids = [team.id for team in current_user.teams]
        wo_query = wo_query.filter(
            db.or_(
                WorkOrder.created_by_id == current_user.id,
                WorkOrder.assigned_to_user_id == current_user.id,
                WorkOrder.assigned_to_team_id.in_(user_team_ids)
            )
        )

    # Use a clone of the query to get the count of active WOs
    active_wo_count_query = wo_query.filter(WorkOrder.status.in_(['Open', 'In Progress']))
    active_wo_count = active_wo_count_query.count()

    # Get the 5 most recent work orders for the list view
    recent_work_orders = wo_query.order_by(WorkOrder.created_at.desc()).limit(5).all()

    # --- 3. FORMAT DATA FOR FULLCALENDAR ---
    # Get all scheduled work orders from the permission-filtered query
    scheduled_wos = wo_query.filter(WorkOrder.scheduled_date.isnot(None)).all()
    calendar_events = []
    for wo in scheduled_wos:
        # Define a color based on priority for the calendar event
        color = '#3f8efc' # Default/Low
        if wo.priority == 'Medium':
            color = '#0dcaf0' # Info
        elif wo.priority == 'High':
            color = '#ffc107' # Warning
        elif wo.priority == 'Urgent':
            color = '#dc3545' # Danger

        calendar_events.append({
            'title': f"#{wo.id}: {wo.title}",
            'start': wo.scheduled_date.isoformat(),
            'url': url_for('view_work_order', wo_id=wo.id), # Make event clickable
            'color': color, # Assign the color
            'borderColor': color
        })
    
    # --- 4. COMPILE FINAL STATS ---
    stats = {
        'total_equipment': total_equipment,
        'operational_equipment': operational_equipment,
        'active_wo_count': active_wo_count,
        'low_stock_items': low_stock_items
    }

    return render_template(
        'index.html', 
        stats=stats, 
        recent_work_orders=recent_work_orders,
        # Pass the events as a JSON string, marked as 'safe' to be rendered correctly in the script tag
        calendar_events=json.dumps(calendar_events)
    )
    
    
# --- SYSTEM ROUTES ---

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_SETTINGS')
def system_settings():
    company = current_user.company
    
    # --- GET or CREATE the MQTT Config for this company ---
    # `company.mqtt_config` works because of the `uselist=False` backref
    mqtt_config = company.mqtt_config
    if not mqtt_config:
        # If no config exists, create an empty one to pass to the template
        mqtt_config = MqttConfig(company_id=company.id)
    
    if request.method == 'POST':
        # Check which form was submitted via a hidden input
        form_name = request.form.get('form_name')

        # NOTE: The "General" tab form is now disabled, so this part is not strictly necessary
        # but is kept for potential future use.
        if form_name == 'general_settings':
            # company.name = request.form.get('company_name') # Company name is read-only
            flash('Company settings updated successfully.', 'success')
        
        elif form_name == 'mqtt_settings':
            # This handles the 'MQTT Server' tab form submission
            host = request.form.get('mqtt_host')
            port = request.form.get('mqtt_port', type=int)

            if not host or not port:
                flash('MQTT Host and Port are required fields.', 'danger')
            else:
                mqtt_config.host = host
                mqtt_config.port = port
                mqtt_config.username = request.form.get('mqtt_username')
                
                # Only update the password if a new one is provided.
                # This prevents accidentally clearing the password.
                if request.form.get('mqtt_password'):
                    mqtt_config.password = request.form.get('mqtt_password')

                # If the mqtt_config object was newly created and doesn't have an ID,
                # it needs to be added to the session before committing.
                if not mqtt_config.id:
                    db.session.add(mqtt_config)
                
                db.session.commit()
                flash('MQTT server settings saved successfully.', 'success')

        return redirect(url_for('system_settings'))

    # --- For a GET request, gather stats for the General info tab ---
    stats = {
        'user_count': User.query.filter_by(company_id=company.id).count(),
        'user_limit': company.user_limit,
        'equipment_count': Equipment.query.filter_by(company_id=company.id).count(),
        'inventory_count': InventoryItem.query.filter_by(company_id=company.id).count(),
        'wo_count': WorkOrder.query.filter_by(company_id=company.id).count(),
    }

    return render_template(
        'settings/index.html', 
        company=company, 
        stats=stats, 
        mqtt_config=mqtt_config
    )


@app.route('/settings/backup')
@login_required
@permission_required('CAN_MANAGE_SETTINGS')
def backup_data():
    """
    Queries all data for the user's company, serializes it to JSON,
    and serves it as a downloadable file.
    """
    company_id = current_user.company_id
    # Eagerly load all collections to make serialization fast
    company = Company.query.options(
        joinedload(Company.categories),
        joinedload(Company.departments),
        joinedload(Company.locations),
        joinedload(Company.vendors).joinedload(Vendor.contacts),
        joinedload(Company.equipment).options(joinedload(Equipment.category), joinedload(Equipment.manufacturer), joinedload(Equipment.location)),
        joinedload(Company.inventory_items).options(joinedload(InventoryItem.category), joinedload(InventoryItem.location), joinedload(InventoryItem.currency), joinedload(InventoryItem.unit_of_measure)),
        joinedload(Company.work_orders).options(joinedload(WorkOrder.equipment), joinedload(WorkOrder.location), joinedload(WorkOrder.created_by), joinedload(WorkOrder.assigned_user), joinedload(WorkOrder.assigned_team)),
        joinedload(Company.users).options(joinedload(User.role), joinedload(User.department)),
        joinedload(Company.roles).joinedload(Role.permissions),
        joinedload(Company.teams).joinedload(Team.members),
        joinedload(Company.units),
        joinedload(Company.currencies)
    ).get(company_id)

    if not company:
        flash('Company data could not be loaded.', 'danger')
        return redirect(url_for('system_settings'))

    # --- 1. GATHER AND SERIALIZE ALL COMPANY DATA ---
    
    # Simple data models
    departments = [{'name': d.name, 'description': d.description} for d in company.departments]
    locations = [{'name': loc.name, 'address': loc.address, 'country': loc.country, 'state': loc.state, 'city': loc.city, 'zip_code': loc.zip_code} for loc in company.locations]
    categories = [{'name': c.name, 'description': c.description, 'category_type': c.category_type, 'color': c.color} for c in company.categories]
    units = [{'name': u.name, 'symbol': u.symbol} for u in company.units]
    currencies = [{'name': c.name, 'code': c.code, 'symbol': c.symbol} for c in company.currencies]
    
    # We only need to back up custom roles
    roles = [{'name': r.name, 'description': r.description, 'permissions': [p.name for p in r.permissions]} 
             for r in company.roles if not r.is_admin and r.name not in ['Manager', 'Technician', 'Viewer']]

    # Users, excluding admins and never exporting passwords
    users = [{'first_name': u.first_name, 'last_name': u.last_name, 'username': u.username, 'email': u.email, 'phone': u.phone, 'role': u.role.name if u.role else None, 'department': u.department.name if u.department else None, 'is_active': u.is_active}
             for u in company.users if u.role and not u.role.is_admin]

    teams = [{'name': t.name, 'description': t.description, 'members': [m.username for m in t.members]} 
             for t in company.teams]
             
    # Vendors with nested contacts
    vendors = []
    for v in company.vendors:
        vendor_data = {'name': v.name, 'description': v.description}
        vendor_data['contacts'] = [{'name': contact.name, 'email': contact.email, 'phone': contact.phone, 'position': contact.position} for contact in v.contacts]
        vendors.append(vendor_data)

    # Equipment (linking by name/ID for portability)
    equipment = [{'name': eq.name, 'equipment_id': eq.equipment_id, 'category': eq.category.name if eq.category else None, 'manufacturer': eq.manufacturer.name if eq.manufacturer else None, 'location': eq.location.name if eq.location else None, 'model': eq.model, 'serial_number': eq.serial_number, 'description': eq.description} 
                 for eq in company.equipment]
    
    inventory_items = [{'name': item.name, 'part_number': item.part_number, 'description': item.description, 'category': item.category.name if item.category else None, 'location': item.location.name if item.location else None, 'unit_cost': str(item.unit_cost) if item.unit_cost is not None else None, 'currency': item.currency.code if item.currency else None, 'unit_of_measure': item.unit_of_measure.name if item.unit_of_measure else None, 'current_stock': item.current_stock, 'minimum_stock': item.minimum_stock} 
                       for item in company.inventory_items]

    work_orders = [{'title': wo.title, 'description': wo.description, 'priority': wo.priority, 'status': wo.status, 'work_order_type': wo.work_order_type, 'equipment': wo.equipment.equipment_id if wo.equipment else None, 'location': wo.location.name if wo.location else None, 'created_by': wo.created_by.username if wo.created_by else None, 'assigned_user': wo.assigned_user.username if wo.assigned_user else None, 'assigned_team': wo.assigned_team.name if wo.assigned_team else None, 'scheduled_date': wo.scheduled_date.isoformat() if wo.scheduled_date else None, 'due_date': wo.due_date.isoformat() if wo.due_date else None} 
                   for wo in company.work_orders]
    
    # --- 2. COMPILE INTO A MASTER DICTIONARY ---
    backup_content = {
        'metadata': {
            'company_name': company.name,
            'export_date': datetime.now(timezone.utc).isoformat(),
            'version': '1.0'
        },
        'data': {
            # Data is ordered from least dependent to most dependent for easier restoration
            'departments': departments,
            'locations': locations,
            'categories': categories,
            'units': units,
            'currencies': currencies,
            'roles': roles,
            'users': users,
            'teams': teams,
            'vendors': vendors,
            'equipment': equipment,
            'inventory_items': inventory_items,
            'work_orders': work_orders,
        }
    }
    
    # --- 3. CREATE AND SERVE THE JSON FILE ---
    json_data = json.dumps(backup_content, indent=4)
    output = io.BytesIO(json_data.encode('utf-8'))
    filename = f"maintaindesk_backup_{company.name.replace(' ', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    
    return Response(
        output,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route('/settings/restore', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_SETTINGS')
def restore_data():
    """
    Restores company data from an uploaded JSON backup file.
    WARNING: This is a destructive operation.
    """
    company_id = current_user.company_id
    
    # --- 1. File Validation ---
    if 'backup_file' not in request.files:
        flash('No backup file provided.', 'danger')
        return redirect(url_for('system_settings'))
    
    file = request.files['backup_file']
    if file.filename == '' or not file.filename.endswith('.json'):
        flash('Invalid file. Please upload a valid .json backup file.', 'danger')
        return redirect(url_for('system_settings'))

    try:
        # --- 2. Read and Parse JSON content ---
        backup_content = json.load(file.stream)
        
        # Basic validation of the backup file structure
        if 'metadata' not in backup_content or 'data' not in backup_content:
            raise ValueError("Invalid backup file format: missing 'metadata' or 'data' keys.")
        
        data_to_restore = backup_content['data']
        
        # --- 3. THE DANGEROUS PART: Delete Existing Data ---
        # This deletes data in reverse order of dependency.
        print(f"--- STARTING RESTORE FOR COMPANY ID: {company_id} ---")
        
        WorkOrder.query.filter_by(company_id=company_id).delete()
        InventoryItem.query.filter_by(company_id=company_id).delete()
        Equipment.query.filter_by(company_id=company_id).delete()
        Vendor.query.filter_by(company_id=company_id).delete() # This will cascade to VendorContact
        Team.query.filter_by(company_id=company_id).delete() # This will clear the team_members table
        # We don't delete the Admin user, but all other users.
        User.query.filter(User.company_id == company_id, User.id != current_user.id).delete()
        # We don't delete default roles.
        Role.query.filter(Role.company_id == company_id, Role.is_admin == False, ~Role.name.in_(['Manager', 'Technician', 'Viewer'])).delete()
        
        # Simpler models
        Currency.query.filter_by(company_id=company_id).delete()
        Unit.query.filter_by(company_id=company_id).delete()
        Category.query.filter_by(company_id=company_id).delete()
        Location.query.filter_by(company_id=company_id).delete()
        Department.query.filter_by(company_id=company_id).delete()

        db.session.commit() # Commit the deletions
        print("Existing data cleared.")

        # --- 4. Re-insert Data in Order of Dependency ---
        # Pre-fetch default/existing items to link against
        print("Re-inserting data...")

        # These simple models can be created first as they have few dependencies.
        for dept_data in data_to_restore.get('departments', []):
            db.session.add(Department(company_id=company_id, **dept_data))
            
        for loc_data in data_to_restore.get('locations', []):
            db.session.add(Location(company_id=company_id, **loc_data))
            
        for cat_data in data_to_restore.get('categories', []):
            # The backup used 'type', but the model uses 'category_type'
            cat_data['category_type'] = cat_data.pop('type', None)
            db.session.add(Category(company_id=company_id, **cat_data))

        for unit_data in data_to_restore.get('units', []):
            db.session.add(Unit(company_id=company_id, **unit_data))

        for curr_data in data_to_restore.get('currencies', []):
            db.session.add(Currency(company_id=company_id, **curr_data))
            
        # Re-create custom roles
        all_permissions_map = {p.name: p for p in Permission.query.all()}
        for role_data in data_to_restore.get('roles', []):
            permission_names = role_data.pop('permissions', [])
            new_role = Role(company_id=company_id, **role_data)
            # Find and link the permission objects
            new_role.permissions = [p for name, p in all_permissions_map.items() if name in permission_names]
            db.session.add(new_role)

        db.session.commit() # Commit these first to get their IDs
        print("Committed basic data (depts, locs, etc).")

        locations_map = {loc.name: loc for loc in Location.query.filter_by(company_id=company_id).all()}
        categories_map = {cat.name: cat for cat in Category.query.filter_by(company_id=company_id).all()}
        departments_map = {dept.name: dept for dept in Department.query.filter_by(company_id=company_id).all()}
        units_map = {unit.name: unit for unit in Unit.query.filter_by(company_id=company_id).all()}
        currencies_map = {curr.code: curr for curr in Currency.query.filter_by(company_id=company_id).all()}
        roles_map = {role.name: role for role in Role.query.filter_by(company_id=company_id).all()}
        
        # We also need a map for users, as they are referenced by Work Orders
        # We fetch all users for the company, including the admin running the restore
        users_map = {user.username: user for user in User.query.filter_by(company_id=company_id).all()}
        
        vendors_map = {}
        
        # Re-insert Users (linking to roles and departments)
        for user_data in data_to_restore.get('users', []):
            role_name = user_data.pop('role', None)
            dept_name = user_data.pop('department', None)
            
            # Generate a new random password; we never restore old ones
            password = generate_random_password()
            
            user = User(
                company_id=company_id,
                password_reset_required=True,
                **user_data
            )
            user.set_password(password)
            
            if role_name and role_name in roles_map:
                user.role_id = roles_map[role_name].id
            if dept_name and dept_name in departments_map:
                user.department_id = departments_map[dept_name].id
            
            db.session.add(user)
            # We need to re-build the users_map after creating them
            users_map[user.username] = user

        db.session.commit() # Commit users to get their IDs
        print("Committed users.")

        # Re-insert Teams (linking to users)
        for team_data in data_to_restore.get('teams', []):
            member_usernames = team_data.pop('members', [])
            team = Team(company_id=company_id, **team_data)
            # Find the user objects from our map
            team.members = [u for uname, u in users_map.items() if uname in member_usernames]
            db.session.add(team)
            
        # Re-insert Vendors
        for vendor_data in data_to_restore.get('vendors', []):
            contacts = vendor_data.pop('contacts', [])
            vendor = Vendor(company_id=company_id, **vendor_data)
            for contact_data in contacts:
                vendor.contacts.append(VendorContact(company_id=company_id, **contact_data))
            db.session.add(vendor)
            vendors_map[vendor.name] = vendor # Populate the vendors map
        
        db.session.commit() # Commit teams and vendors
        print("Committed teams and vendors.")

        # Re-insert Equipment (linking to vendors, categories, locations)
        for eq_data in data_to_restore.get('equipment', []):
            category_name = eq_data.pop('category', None)
            manufacturer_name = eq_data.pop('manufacturer', None)
            location_name = eq_data.pop('location', None)
            
            eq_data['category_id'] = categories_map.get(category_name).id if category_name in categories_map else None
            eq_data['manufacturer_id'] = vendors_map.get(manufacturer_name).id if manufacturer_name in vendors_map else None
            eq_data['location_id'] = locations_map.get(location_name).id if location_name in locations_map else None
            
            db.session.add(Equipment(company_id=company_id, **eq_data))
            
        # Re-insert Inventory Items
        for item_data in data_to_restore.get('inventory_items', []):
            category_name = item_data.pop('category', None)
            location_name = item_data.pop('location', None)
            currency_code = item_data.pop('currency', None)
            unit_name = item_data.pop('unit_of_measure', None)

            item_data['category_id'] = categories_map.get(category_name).id if category_name in categories_map else None
            item_data['location_id'] = locations_map.get(location_name).id if location_name in locations_map else None
            item_data['currency_id'] = currencies_map.get(currency_code).id if currency_code in currencies_map else None
            item_data['unit_of_measure_id'] = units_map.get(unit_name).id if unit_name in units_map else None
            
            db.session.add(InventoryItem(company_id=company_id, **item_data))

        db.session.commit() # Commit equipment and inventory to get their IDs
        print("Committed equipment and inventory.")

        # Re-build maps for newly created equipment and inventory
        equipment_map = {eq.equipment_id: eq for eq in Equipment.query.filter_by(company_id=company_id).all()}

        # Re-insert Work Orders (most dependent model)
        for wo_data in data_to_restore.get('work_orders', []):
            equipment_id = wo_data.pop('equipment', None)
            location_name = wo_data.pop('location', None)
            created_by_username = wo_data.pop('created_by', None)
            assigned_user_username = wo_data.pop('assigned_user', None)
            assigned_team_name = wo_data.pop('assigned_team', None) # Assuming you add this to backup

            wo_data['equipment_id'] = equipment_map.get(equipment_id).id if equipment_id in equipment_map else None
            wo_data['location_id'] = locations_map.get(location_name).id if location_name in locations_map else None
            wo_data['created_by_id'] = users_map.get(created_by_username).id if created_by_username in users_map else None
            wo_data['assigned_to_user_id'] = users_map.get(assigned_user_username).id if assigned_user_username in users_map else None
            # wo_data['assigned_to_team_id'] = ... # Logic to find team by name
            
            db.session.add(WorkOrder(company_id=company_id, **wo_data))
        
        db.session.commit()
        print("Restore complete.")
        
        flash('Data restore successful. Your company data has been overwritten with the backup file.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'A critical error occurred during the restore process: {e}. Your data has NOT been changed.', 'danger')
        print(f"Error in restore_data: {e}")

    return redirect(url_for('system_settings'))

# --- MIDDLEWARE FOR FORCING PASSWORD CHANGE ---

@app.before_request
def check_password_reset_required():
    """
    Runs before every request. If the user is logged in and needs to reset
    their password, it redirects them to the change_password page.
    """
    # 1. Check if the user is authenticated and the flag is set
    if current_user.is_authenticated and current_user.password_reset_required:
        
        # 2. Define a list of "allowed" pages the user can visit
        #    They must be able to access the change password page and logout
        allowed_endpoints = ['change_password', 'logout', 'static']
        
        # 3. If they are trying to go somewhere else, redirect them
        if request.endpoint not in allowed_endpoints:
            flash('For your security, you must change your temporary password before proceeding.', 'warning')
            return redirect(url_for('change_password'))
        
@app.after_request
def commit_notification_logs(response):
    """
    Runs after each request. If any notification logs were queued,
    this function commits them to the database.
    """
    # Check if the queue exists and has items
    if hasattr(g, 'notification_logs') and g.notification_logs:
        try:
            for log_data in g.notification_logs:
                log_entry = NotificationLog(**log_data)
                db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error committing notification logs: {e}")
    return response
        
# --- CUSTOM ERROR HANDLERS ---
        
@app.errorhandler(403)
def forbidden_error(error):
    """
    Custom handler for 403 Forbidden errors.
    Flashes a message and redirects the user.
    """
    flash('You do not have the required permissions to access this page.', 'danger')
    
    # Try to redirect to the user's previous page, with a fallback to the index.
    # The 'referrer' header contains the URL of the page the user was on before this request.
    return redirect(request.referrer or url_for('index'))

# --- CUSTOM FLASH FUNCTION ---

def flash(message, category='message'):
    """
    Custom flash function that queues a message to be logged to the DB
    at the end of the request.
    """
    if current_user.is_authenticated:
        # If the log queue doesn't exist for this request, create it
        if 'notification_logs' not in g:
            g.notification_logs = []
        
        log_message = str(message)
        if category == 'credentials':
            log_message = "A new user's credentials were generated."

        # Add the log data to our request-specific queue
        g.notification_logs.append({
            'user_id': current_user.id,
            'message': log_message,
            'category': category
        })

    # Call the original Flask flash function
    flask_flash(message, category)
    
# --- CONTEXT PROCESSOR FOR TEMPLATES ---

@app.context_processor
def inject_permissions():
    """
    Injects a 'has_permission' function into the template context
    so it can be used in any Jinja template.
    """
    def has_permission(permission_name):
        # Always return True for Admins, they can do everything
        if current_user.is_authenticated and current_user.role and current_user.role.is_admin:
            return True
        # Check for a specific permission in the user's role
        if current_user.is_authenticated and current_user.role and current_user.role.permissions:
            return permission_name in [p.name for p in current_user.role.permissions]
        return False
        
    return dict(has_permission=has_permission)
        
# --- ROLE MANAGEMENT ROUTES ---

@app.route('/roles')
@login_required
@permission_required('CAN_MANAGE_ROLES')
def manage_roles():
    search_query = request.args.get('q', '').strip()
    
    # Base query to get roles for the current user's company
    query = Role.query.filter(Role.company_id == current_user.company_id)

    if search_query:
        # Add a filter condition if a search query exists
        query = query.filter(Role.name.ilike(f'%{search_query}%'))

    # Eagerly load the user count for each role to avoid N+1 queries
    # This is an efficient way to count related users.
    query = query.outerjoin(User).group_by(Role.id).add_columns(func.count(User.id).label('user_count'))

    # Order and execute the query
    roles_with_count = query.order_by(Role.is_admin.desc(), Role.name).all()

    return render_template(
        'roles/manage_roles.html',
        roles_with_count=roles_with_count,
        search_query=search_query
    )

@app.route('/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_ROLES')
def edit_role(role_id):
    role = Role.query.get_or_404(role_id)
    if role.company_id != current_user.company_id or role.is_admin:
        flash('This role cannot be modified.', 'warning')
        return redirect(url_for('manage_roles'))

    if request.method == 'POST':
        role.name = request.form.get('name')
        role.description = request.form.get('description')
        selected_permission_ids = request.form.getlist('permissions')
        role.permissions = Permission.query.filter(Permission.id.in_(selected_permission_ids)).all()
        db.session.commit()
        flash(f'Role "{role.name}" has been updated.', 'success')
        return redirect(url_for('manage_roles'))

    # --- THIS IS THE NEW LOGIC ---
    # Group all available permissions by a category prefix
    all_permissions = Permission.query.order_by(Permission.name).all()
    grouped_permissions = {
        'General': [],
        'Users & Teams': [],
        'Work Orders': [],
        'Assets': [],
        'Vendors': [],
        'Company Data': [],
        'System & Reporting': [],
    }
    
    for perm in all_permissions:
        if 'USER' in perm.name or 'ROLE' in perm.name or 'TEAM' in perm.name:
            grouped_permissions['Users & Teams'].append(perm)
        elif 'WORK_ORDER' in perm.name:
            grouped_permissions['Work Orders'].append(perm)
        elif 'EQUIPMENT' in perm.name or 'INVENTORY' in perm.name or 'ASSET' in perm.name:
            grouped_permissions['Assets'].append(perm)
        elif 'VENDOR' in perm.name:
            grouped_permissions['Vendors'].append(perm)
        elif any(p in perm.name for p in ['CATEGORIES', 'DEPARTMENTS', 'LOCATIONS', 'UNITS', 'CURRENCIES']):
            grouped_permissions['Company Data'].append(perm)
        elif any(p in perm.name for p in ['REPORT', 'SETTING', 'BROADCAST']):
            grouped_permissions['System & Reporting'].append(perm)
        else: # Fallback for general permissions like CAN_VIEW_DASHBOARD
            grouped_permissions['General'].append(perm)
    # --- END OF NEW LOGIC ---

    return render_template('roles/edit_role.html', role=role, grouped_permissions=grouped_permissions)

# --- USER MANAGEMENT ROUTES ---

@app.route('/users')
@login_required
@permission_required('CAN_MANAGE_USERS')
def manage_users():
    search_query = request.args.get('q', '').strip()
    
    # Base query for all users in the current user's company
    query = User.query.filter(User.company_id == current_user.company_id)
    
    # Join with the Role table to filter out any user who has an admin role
    # This ensures Admins do not appear in the management list.
    query = query.join(User.role).filter(Role.is_admin == False)

    # Eagerly load Role and Department relationships to prevent the N+1 query problem
    # and make the data available in the template without extra database hits.
    query = query.options(
        joinedload(User.role),
        joinedload(User.department)
    )

    if search_query:
        search_term = f"%{search_query}%"
        # Search by username, first name, last name, or email
        query = query.filter(
            db.or_(
                User.username.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term),
                User.email.ilike(search_term)
            )
        )

    # Order the results for consistent display
    users_list = query.order_by(User.first_name, User.last_name).all()
    
    return render_template(
        'users/index.html',
        users_list=users_list,
        search_query=search_query
    )
    
def generate_random_password(length=12):
    """Generates a secure, random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    # Ensure the password has at least one of each character type for complexity
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]
    # Fill the rest of the password length with random characters
    for _ in range(length - len(password)):
        password.append(random.choice(characters))
    
    # Shuffle the list to ensure randomness and join to form the final password string
    random.shuffle(password)
    return "".join(password)

def generate_unique_username(first_name, company_id):
    """Generates a unique username based on the first name, avoiding collisions."""
    # Sanitize the first name to create a base username
    base_username = ''.join(filter(str.isalnum, first_name.lower()))
    if not base_username: # Fallback if name has no alphanumeric characters
        base_username = 'user'
        
    username = base_username
    counter = 1
    # Check if the generated username already exists in the company
    while User.query.filter_by(company_id=company_id, username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
    return username

@app.route('/users/download-template')
@login_required
@permission_required('CAN_MANAGE_USERS')
def download_user_template():
    """Generates and serves a CSV template for bulk user import."""
    
    # --- Define CSV headers ---
    headers = ["FirstName", "LastName", "Email", "Role", "Department", "Phone"]
    
    # --- Create a CSV in memory ---
    # Using io.StringIO allows us to treat a string as a file
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write the header row
    writer.writerow(headers)
    
    # Write an example row to guide the user
    example_row = ["John", "Doe", "john.doe@example.com", "Technician", "Maintenance", "555-1234"]
    writer.writerow(example_row)
    
    # --- Prepare the response for download ---
    # We need to get the content of our in-memory file
    output.seek(0)
    
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=user_import_template.csv"}
    )

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_USERS')
def add_user():
    # Fetch data needed for the form's dropdowns
    form_data = get_profile_form_data() 

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        email = request.form.get('email', '').strip()
        role_id = request.form.get('role_id')

        # --- 1. Basic Form Validation ---
        if not all([first_name, email, role_id]):
            flash('First Name, Email, and Role are required fields.', 'danger')
            return render_template('users/form.html', form_data=form_data, user=None)
        
        # --- 2. User Limit Check ---
        # Get the current number of users in the company
        user_count = User.query.filter_by(company_id=current_user.company_id).count()
        # Get the user limit from the company object
        user_limit = current_user.company.user_limit

        if user_count >= user_limit:
            flash(f'You have reached your company\'s limit of {user_limit} users. Please contact support to upgrade your plan.', 'danger')
            return render_template('users/form.html', form_data=form_data, user=None)
        
        # --- 3. Data Uniqueness Validation ---
        if User.query.filter_by(company_id=current_user.company_id, email=email).first():
            flash(f'A user with the email "{email}" already exists in this company.', 'warning')
            return render_template('users/form.html', form_data=form_data, user=None)

        # --- 4. Generate Data ---
        username = generate_unique_username(first_name, current_user.company_id)
        password = generate_random_password()

        # --- 5. Create and Save User Object ---
        try:
            new_user = User(
                company_id=current_user.company_id,
                first_name=first_name,
                last_name=request.form.get('last_name', '').strip(),
                username=username,
                email=email,
                role_id=role_id,
                department_id=request.form.get('department_id') or None,
                phone=request.form.get('phone', '').strip(),
                is_active='is_active' in request.form,
                password_reset_required=True
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # --- Success Feedback ---
            flash(f'User "{first_name}" created successfully! Provide them with their credentials below.', 'success')
            flash(f'Username: {username}', 'info')
            flash((password, new_user.id), 'credentials')
            
            return redirect(url_for('manage_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the user: {e}', 'danger')

    # For a GET request
    return render_template('users/form.html', form_data=form_data, user=None)

@app.route('/users/bulk-import', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_USERS')
def bulk_import_users():
    # --- 1. File Handling and Validation ---
    if 'csv_file' not in request.files:
        flash('No file part in the request.', 'danger')
        return redirect(url_for('add_user'))
    
    file = request.files['csv_file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        flash('Please select a valid .csv file to upload.', 'danger')
        return redirect(url_for('add_user'))

    # --- 2. User Limit Check for Bulk Action ---
    try:
        # Read the file content into memory to count the rows first
        file_content = file.stream.read().decode("UTF8")
        stream = io.StringIO(file_content, newline=None)
        
        # Count the number of data rows in the CSV (subtract 1 for the header)
        num_new_users = len(file_content.strip().split('\n')) - 1
        
        if num_new_users <= 0:
            flash('The uploaded CSV file is empty or contains no data rows.', 'warning')
            return redirect(url_for('add_user'))

        user_count = User.query.filter_by(company_id=current_user.company_id).count()
        user_limit = current_user.company.user_limit

        if (user_count + num_new_users) > user_limit:
            flash(f'Import failed: You currently have {user_count} of {user_limit} users. Importing {num_new_users} new users would exceed your limit.', 'danger')
            return redirect(url_for('add_user'))

        # Reset the stream to be read by DictReader after counting
        stream.seek(0)
        csv_reader = csv.DictReader(stream)
    except Exception as e:
        flash(f'Error reading CSV file: {e}', 'danger')
        return redirect(url_for('add_user'))
        
    # --- 3. CSV Parsing and User Creation ---
    created_count = 0
    error_count = 0
    new_user_credentials = []

    try:
        company_roles = {role.name.lower(): role for role in Role.query.filter_by(company_id=current_user.company_id).all()}
        company_depts = {dept.name.lower(): dept for dept in Department.query.filter_by(company_id=current_user.company_id).all()}

        for row_num, row in enumerate(csv_reader, 2):
            first_name = row.get('FirstName', '').strip()
            email = row.get('Email', '').strip()
            role_name = row.get('Role', '').strip()

            if not all([first_name, email, role_name]):
                error_count += 1
                flash(f"Skipping row {row_num}: Missing required fields (FirstName, Email, Role).", 'warning')
                continue
            
            if User.query.filter_by(company_id=current_user.company_id, email=email).first():
                error_count += 1
                flash(f"Skipping row {row_num}: User with email '{email}' already exists.", 'warning')
                continue

            role = company_roles.get(role_name.lower())
            if not role:
                error_count += 1
                flash(f"Skipping row {row_num}: Role '{role_name}' does not exist.", 'warning')
                continue

            dept_name = row.get('Department', '').strip()
            department = company_depts.get(dept_name.lower()) if dept_name else None
            
            username = generate_unique_username(first_name, current_user.company_id)
            password = generate_random_password()
            
            new_user = User(
                company_id=current_user.company_id,
                first_name=first_name,
                last_name=row.get('LastName', '').strip(),
                email=email,
                username=username,
                role_id=role.id,
                department_id=department.id if department else None,
                phone=row.get('Phone', '').strip(),
                is_active=True,
                password_reset_required=True
            )
            new_user.set_password(password)
            db.session.add(new_user)
            created_count += 1
            
            new_user_credentials.append({
                'FirstName': first_name,
                'LastName': row.get('LastName', '').strip(),
                'Email': email,
                'Username': username,
                'Password': password
            })

        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'A critical error occurred during the import process: {e}', 'danger')
        return redirect(url_for('add_user'))

    # --- 4. Generate and Serve the Credentials File or Show Errors ---
    if created_count > 0:
        flash(f'Successfully imported {created_count} new users. Please download the credentials file.', 'success')
        if error_count > 0:
            flash(f'Skipped {error_count} rows due to errors or existing data. Please check warnings.', 'warning')

        output = io.StringIO()
        fieldnames = ['FirstName', 'LastName', 'Email', 'Username', 'Password']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(new_user_credentials)
        output.seek(0)
        
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=new_user_credentials_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.csv"}
        )
    
    if error_count > 0:
        flash(f'Import failed. Skipped {error_count} rows due to errors. Please check warnings and try again.', 'danger')
        return redirect(url_for('add_user'))

    return redirect(url_for('manage_users'))

@app.route('/users/view/<int:user_id>')
@login_required
@permission_required('CAN_MANAGE_USERS')
def view_user_profile(user_id):
    user = User.query.options(joinedload(User.role), joinedload(User.department)).get_or_404(user_id)
    if user.company_id != current_user.company_id:
        abort(403)
    # Re-use the existing profile template
    return render_template('profile/view.html', user=user)


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_USERS')
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    
    # --- Security Checks ---
    # 1. User must be in the same company
    if user_to_edit.company_id != current_user.company_id:
        abort(403)
    # 2. An admin cannot be edited from this page
    if user_to_edit.role and user_to_edit.role.is_admin:
        flash('Administrator accounts cannot be edited from this page.', 'warning')
        next_url = request.form.get('next_url') or url_for('manage_users')
        return redirect(next_url)

    # --- Hierarchical Permission Check ---
    is_current_user_admin = current_user.role and current_user.role.is_admin
    # You can manage the user if you're an admin OR your role level is higher (lower number)
    can_manage_user = is_current_user_admin or (current_user.role.level < user_to_edit.role.level)
    
    if not can_manage_user:
        flash('You do not have permission to edit this user.', 'danger')
        next_url = request.form.get('next_url') or url_for('manage_users')
        return redirect(next_url)

    if request.method == 'POST':
        # --- Uniqueness validation for username ---
        new_username = request.form.get('username')
        existing_user = User.query.filter(User.username == new_username, User.id != user_to_edit.id, User.company_id == current_user.company_id).first()
        if existing_user:
            flash('That username is already taken. Please choose another.', 'warning')
            form_data = get_profile_form_data()
            return render_template('profile/edit.html', user=user_to_edit, is_admin=is_current_user_admin, form_data=form_data)

        # --- Update Fields ---
        user_to_edit.username = new_username
        user_to_edit.first_name = request.form.get('first_name')
        user_to_edit.last_name = request.form.get('last_name')
        user_to_edit.phone = request.form.get('phone')

        # --- Admin-only updatable fields ---
        if is_current_user_admin:
            user_to_edit.department_id = request.form.get('department_id') or None
            user_to_edit.role_id = request.form.get('role_id') or None
            user_to_edit.is_active = 'is_active' in request.form
            
            # An admin can change another user's email
            new_email = request.form.get('email')
            if new_email and new_email != user_to_edit.email:
                # Check if the new email is already taken
                existing_email_user = User.query.filter(User.email == new_email, User.company_id == current_user.company_id).first()
                if existing_email_user:
                    flash(f'The email "{new_email}" is already in use.', 'warning')
                    form_data = get_profile_form_data()
                    return render_template('profile/edit.html', user=user_to_edit, is_admin=is_current_user_admin, form_data=form_data)
                user_to_edit.email = new_email
        
        db.session.commit()
        flash(f'Profile for "{user_to_edit.username}" has been updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    # For a GET request, get the data needed for dropdowns
    form_data = get_profile_form_data()
    # Re-use the existing profile edit template
    next_url = request.args.get('next', url_for('manage_users'))
    form_data = get_profile_form_data()
    return render_template('profile/edit.html', user=user_to_edit, is_admin=is_current_user_admin, form_data=form_data, next_url=next_url)

def send_invite_email(user):
    """Generates and sends a password-setting email to a new user."""
    token = user.get_reset_token(expires_sec=604800) # Token valid for 7 days
    msg = Message(
        'Welcome to MaintainDesk! Set Your Password',
        recipients=[user.email]
    )
    # The _external=True is crucial to generate a full URL
    invite_url = url_for('set_password_from_invite', token=token, _external=True)
    
    # You can use a nice HTML template for this email
    msg.body = f'''Welcome to MaintainDesk!

To set up your account and choose your password, please visit the following link:
{invite_url}

If you did not expect this invitation, you can safely ignore this email.

Thanks,
The MaintainDesk Team
'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    
def send_work_order_assignment_email(work_order):
    """Sends a notification email to an assigned user or all members of an assigned team."""
    
    # Determine the recipient(s)
    recipients = []
    assigned_to_name = "Unassigned"
    if work_order.assigned_user:
        recipients.append(work_order.assigned_user.email)
        assigned_to_name = f"{work_order.assigned_user.first_name} {work_order.assigned_user.last_name}"
    elif work_order.assigned_team:
        # Eagerly load members if not already loaded
        team = Team.query.options(joinedload(Team.members)).get(work_order.assigned_to_team_id)
        recipients = [member.email for member in team.members]
        assigned_to_name = f"{team.name} (Team)"

    if not recipients:
        return # Do nothing if no one is assigned

    msg = Message(
        f"New Work Order Assigned: #{work_order.id} - {work_order.title}",
        recipients=recipients
    )

    # Use a simple but informative HTML template for the email
    view_url = url_for('view_work_order', wo_id=work_order.id, _external=True)
    msg.html = f"""
    <p>Hello,</p>
    <p>A new work order has been assigned to you or your team:</p>
    <h3><a href="{view_url}">Work Order #{work_order.id}: {work_order.title}</a></h3>
    <ul>
        <li><strong>Equipment:</strong> {work_order.equipment.name if work_order.equipment else 'N/A'}</li>
        <li><strong>Location:</strong> {work_order.location.name if work_order.location else 'N/A'}</li>
        <li><strong>Priority:</strong> {work_order.priority}</li>
        <li><strong>Assigned To:</strong> {assigned_to_name}</li>
        <li><strong>Due Date:</strong> {work_order.due_date.strftime('%Y-%m-%d') if work_order.due_date else 'Not set'}</li>
    </ul>
    <p>Please review the details at your earliest convenience.</p>
    <p>Thanks,<br>The MaintainDesk System</p>
    """
    
    try:
        mail.send(msg)
        print(f"Work order assignment email sent for WO #{work_order.id}")
    except Exception as e:
        print(f"Error sending WO assignment email for WO #{work_order.id}: {e}")
        
def send_approval_request_email(work_order):
    """Finds all users with approval permissions and sends them a notification."""
    
    approver_permission = Permission.query.filter_by(name='CAN_APPROVE_WORK_ORDER').first()
    if not approver_permission:
        print("Warning: CAN_APPROVE_WORK_ORDER permission not found.")
        return

    approvers = User.query.join(Role).filter(
        User.company_id == work_order.company_id,
        User.is_active == True,
        db.or_(
            Role.is_admin == True,
            Role.permissions.contains(approver_permission)
        )
    ).all()

    if not approvers:
        print(f"Warning: No active approvers found for company ID {work_order.company_id} to approve WO #{work_order.id}")
        return

    # Separate the list of emails.
    recipient_emails = [user.email for user in approvers]
    
    # Use the first approver as the main recipient and BCC the rest.
    # This prevents the email from going to the creator.
    main_recipient = recipient_emails.pop(0)
    bcc_recipients = recipient_emails # The rest of the list
    
    msg = Message(
        f"New Work Order Request for Approval: #{work_order.id}",
        recipients=[main_recipient],
        bcc=bcc_recipients
    )

    requests_url = url_for('manage_work_orders', _external=True)
    msg.html = f"""
    <p>A new work order has been submitted and requires approval.</p>
    <h3>Work Order #{work_order.id}: {work_order.title}</h3>
    <ul>
        <li><strong>Created By:</strong> {work_order.created_by.first_name} {work_order.created_by.last_name}</li>
        <li><strong>Equipment:</strong> {work_order.equipment.name if work_order.equipment else 'N/A'}</li>
        <li><strong>Priority:</strong> {work_order.priority}</li>
    </ul>
    <p>Please visit the Work Orders page in MaintainDesk to review and approve or reject this request.</p>
    <p><a href="{requests_url}">View Work Order Requests</a></p>
    """
    
    try:
        mail.send(msg)
        print(f"Approval request email sent for WO #{work_order.id} to {len(approvers)} approvers.")
    except Exception as e:
        print(f"Error sending approval request email for WO #{work_order.id}: {e}")
        
def send_wo_status_change_email(work_order, is_approved):
    """
    Emails the creator of a work order about its approval or rejection.
    Prioritizes guest reporters if their email was provided.
    """
    recipient_email = None
    recipient_name = "User"

    # --- THIS IS THE CORRECTED LOGIC ---
    # Use getattr for safe access on both real and temp objects
    guest_email = getattr(work_order, 'guest_reporter_email', None)
    guest_name = getattr(work_order, 'guest_reporter_name', None)

    if guest_email:
        recipient_email = guest_email
        recipient_name = guest_name or "there"
    elif work_order.created_by and "system_reporter" not in work_order.created_by.username:
        recipient_email = work_order.created_by.email
        recipient_name = work_order.created_by.first_name
    
    if not recipient_email:
        print(f"No recipient email found for WO #{work_order.id}. Cannot send status change notification.")
        return

    status_text = "Approved" if is_approved else "Rejected"
    
    msg = Message(
        f"Update on Your Work Order Request: #{work_order.id} - {status_text}",
        recipients=[recipient_email]
    )
    
    # This logic is now safe because rejected WOs are deleted
    if is_approved:
        view_url = url_for('view_work_order', wo_id=work_order.id, _external=True)
        link_text = f"<h3><a href=\"{view_url}\">Work Order #{work_order.id}: {work_order.title}</a></h3>"
    else:
        link_text = f"<h3>Work Order Request #{work_order.id}: {work_order.title}</h3>"

    rejection_reason_html = ""
    if not is_approved and work_order.rejection_reason:
        rejection_reason_html = f"<p><strong>Reason for Rejection:</strong> {work_order.rejection_reason}</p>"

    msg.html = f"""
    <p>Hello {recipient_name},</p>
    <p>An update has been made to a work order you requested:</p>
    {link_text}
    <p>The new status is: <strong>{status_text}</strong></p>
    {rejection_reason_html}
    <p>Thanks,<br>The MaintainDesk System</p>
    """
    
    try:
        mail.send(msg)
        print(f"WO status change email sent successfully for WO #{work_order.id} to {recipient_email}")
    except Exception as e:
        print(f"Error sending WO status change email for WO #{work_order.id}: {e}")

@app.route('/users/invite', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_USERS')
def invite_user():
    form_data = get_profile_form_data()
    if request.method == 'POST':
        # --- This logic is almost identical to add_user ---
        first_name = request.form.get('first_name', '').strip()
        email = request.form.get('email', '').strip()
        role_id = request.form.get('role_id')

        if not all([first_name, email, role_id]):
            flash('First Name, Email, and Role are required fields.', 'danger')
            return render_template('users/invite_form.html', form_data=form_data)
        
        if User.query.filter_by(company_id=current_user.company_id, email=email).first():
            flash(f'A user with the email "{email}" already exists.', 'warning')
            return render_template('users/invite_form.html', form_data=form_data)

        username = generate_unique_username(first_name, current_user.company_id)
        
        new_user = User(
            company_id=current_user.company_id,
            first_name=first_name,
            last_name=request.form.get('last_name', '').strip(),
            username=username,
            email=email,
            role_id=role_id,
            department_id=request.form.get('department_id') or None,
            phone=request.form.get('phone'),
            is_active='is_active' in request.form,
            # We set a placeholder password that can't be used
            password_hash=bcrypt.generate_password_hash('!UNSET_PASSWORD!').decode('utf-8')
        )
        db.session.add(new_user)
        db.session.commit()

        # --- Send the invitation email ---
        if send_invite_email(new_user):
            flash(f'Invitation sent successfully to {email}.', 'success')
        else:
            flash('User was created, but the invitation email could not be sent. Please check mail server configuration.', 'danger')
        
        return redirect(url_for('invite_user'))

    return render_template('users/invite_form.html', form_data=form_data)


@app.route('/users/set-password/<token>', methods=['GET', 'POST'])
def set_password_from_invite(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired invitation link.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            # --- FIX IS HERE ---
            return render_template('users/set_password_form.html', token=token, hide_sidebar=True)

        user.set_password(password)
        user.password_reset_required = False
        db.session.commit()
        flash('Your password has been set! You can now log in.', 'success')
        return redirect(url_for('login'))

    # --- AND FIX IS HERE ---
    return render_template('users/set_password_form.html', token=token, hide_sidebar=True)

@app.route('/users/bulk-invite', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_USERS')
def bulk_invite_users():
    if 'csv_file' not in request.files:
        flash('No file part in the request.', 'danger')
        return redirect(url_for('invite_user'))
    
    file = request.files['csv_file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        flash('Please select a valid .csv file to upload.', 'danger')
        return redirect(url_for('invite_user'))

    error_count = 0
    newly_created_users = [] # Store the user objects to email them later

    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        # Pre-fetch for efficiency
        company_roles = {role.name.lower(): role for role in Role.query.filter_by(company_id=current_user.company_id).all()}
        company_depts = {dept.name.lower(): dept for dept in Department.query.filter_by(company_id=current_user.company_id).all()}

        rows_to_process = list(csv_reader) # Read all rows into a list
        if not rows_to_process:
            flash('The uploaded CSV file is empty.', 'warning')
            return redirect(url_for('invite_user'))

        for row_num, row in enumerate(rows_to_process, 2):
            first_name = row.get('FirstName', '').strip()
            email = row.get('Email', '').strip()
            role_name = row.get('Role', '').strip()

            # --- Row-level Validation (same as bulk_import) ---
            if not all([first_name, email, role_name]):
                error_count += 1; flash(f"Skipping row {row_num}: Missing required fields.", 'warning'); continue
            if User.query.filter_by(company_id=current_user.company_id, email=email).first():
                error_count += 1; flash(f"Skipping row {row_num}: Email '{email}' already exists.", 'warning'); continue
            role = company_roles.get(role_name.lower())
            if not role:
                error_count += 1; flash(f"Skipping row {row_num}: Role '{role_name}' does not exist.", 'warning'); continue
            
            dept_name = row.get('Department', '').strip()
            department = company_depts.get(dept_name.lower()) if dept_name else None
            username = generate_unique_username(first_name, current_user.company_id)
            
            new_user = User(
                company_id=current_user.company_id, first_name=first_name,
                last_name=row.get('LastName', '').strip(), email=email,
                username=username, role_id=role.id,
                department_id=department.id if department else None, phone=row.get('Phone', '').strip(),
                is_active=True, password_hash=bcrypt.generate_password_hash('!UNSET_PASSWORD!').decode('utf-8')
            )
            db.session.add(new_user)
            newly_created_users.append(new_user)
        
        # --- Commit all users in one transaction ---
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'A critical error occurred during the import process: {e}', 'danger')
        return redirect(url_for('invite_user'))

    # --- 3. Send Emails AFTER successful commit ---
    email_success_count = 0
    email_fail_count = 0
    if newly_created_users:
        for user in newly_created_users:
            if send_invite_email(user):
                email_success_count += 1
            else:
                email_fail_count += 1
    
    # --- 4. Final Feedback ---
    if email_success_count > 0:
        flash(f'Successfully created and sent {email_success_count} invitations.', 'success')
    if email_fail_count > 0:
        flash(f'Created {email_fail_count} users, but failed to send their invitation emails. Please check mail server configuration.', 'danger')
    if error_count > 0:
        flash(f'Skipped {error_count} rows from the CSV due to errors or existing data.', 'warning')

    return redirect(url_for('invite_user'))

@app.route('/users/send-credentials/<int:user_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_USERS')
def send_credentials_email(user_id):
    user = User.query.get_or_404(user_id)
    if user.company_id != current_user.company_id:
        abort(403)

    # We need the password, but it's hashed. This is why this feature
    # can only be used immediately after creation, when we have the password.
    password = request.form.get('password')
    if not password:
        flash('Password not provided. Cannot send email.', 'danger')
        return redirect(url_for('manage_users'))

    msg = Message(
        'Your New Account Credentials for MaintainDesk',
        recipients=[user.email]
    )
    
    # It's good practice to use a simple HTML template for emails
    msg.html = f"""
    <p>Hello {user.first_name},</p>
    <p>An account has been created for you on MaintainDesk.</p>
    <p>You can log in using the following credentials:</p>
    <ul>
        <li><strong>Login Email:</strong> {user.email}</li>
        <li><strong>Initial Password:</strong> <code>{password}</code></li>
    </ul>
    <p>For your security, you will be required to change this password upon your first login.</p>
    <p>Thanks,<br>The MaintainDesk Team</p>
    """
    
    try:
        mail.send(msg)
        flash(f'Credentials successfully sent to {user.email}.', 'success')
    except Exception as e:
        print(f"Error sending credentials email: {e}")
        flash('Failed to send email. Please check your mail server configuration.', 'danger')

    return redirect(url_for('manage_users'))

# --- CATEGORY MANAGEMENT ROUTES ---

@app.route('/categories')
@login_required
@permission_required('CAN_MANAGE_CATEGORIES')
def manage_categories():
    search_query = request.args.get('q', '').strip()
    
    query = Category.query.filter(Category.company_id == current_user.company_id)

    if search_query:
        # Filter by name if a search query is provided (case-insensitive)
        query = query.filter(Category.name.ilike(f'%{search_query}%'))

    categories = query.order_by(Category.name).all()
    
    return render_template(
        'categories/index.html', 
        categories=categories, 
        search_query=search_query
    )

@app.route('/categories/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_CATEGORIES')
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')
        category_type = request.form.get('category_type')

        if not name or not category_type:
            flash('Category Name and Type are required fields.', 'danger')
            return redirect(url_for('add_category'))

        new_category = Category(
            company_id=current_user.company_id,
            name=name,
            description=request.form.get('description'),
            category_type=category_type,
            is_active='is_active' in request.form,
            color=request.form.get('color')
        )
        db.session.add(new_category)
        db.session.commit()
        flash(f'Category "{name}" created successfully.', 'success')
        return redirect(url_for('manage_categories'))
        
    return render_template('categories/form.html', category=None)

@app.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_CATEGORIES')
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        category.name = request.form.get('name')
        category.category_type = request.form.get('category_type')
        category.description = request.form.get('description')
        category.is_active = 'is_active' in request.form
        category.color = request.form.get('color')
        
        db.session.commit()
        flash(f'Category "{category.name}" updated successfully.', 'success')
        return redirect(url_for('manage_categories'))

    return render_template('categories/form.html', category=category)

@app.route('/categories/delete/<int:category_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_CATEGORIES')
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.company_id != current_user.company_id:
        abort(403)
    
    # Future-proofing: Add a check here if categories are linked to assets
    # if category.assets:
    #     flash('Cannot delete category as it is currently in use.', 'danger')
    #     return redirect(url_for('manage_categories'))

    db.session.delete(category)
    db.session.commit()
    flash(f'Category "{category.name}" has been deleted.', 'success')
    return redirect(url_for('manage_categories'))

# --- DEPARTMENT MANAGEMENT ROUTES ---

@app.route('/departments')
@login_required
@permission_required('CAN_MANAGE_DEPARTMENTS')
def manage_departments():
    search_query = request.args.get('q', '').strip()
    query = Department.query.filter(Department.company_id == current_user.company_id)
    if search_query:
        query = query.filter(Department.name.ilike(f'%{search_query}%'))
    departments = query.order_by(Department.name).all()
    return render_template(
        'departments/index.html',
        departments=departments,
        search_query=search_query
    )

@app.route('/departments/add', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_DEPARTMENTS')
def add_department():
    name = request.form.get('name')
    if not name:
        flash('Department Name is a required field.', 'danger')
    else:
        new_dept = Department(
            company_id=current_user.company_id,
            name=name,
            description=request.form.get('description'),
            is_active=True
        )
        db.session.add(new_dept)
        db.session.commit()
        flash(f'Department "{name}" created successfully.', 'success')
    return redirect(url_for('manage_departments'))

@app.route('/departments/edit/<int:dept_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_DEPARTMENTS')
def edit_department(dept_id):
    department = Department.query.get_or_404(dept_id)
    if department.company_id != current_user.company_id:
        abort(403)
    
    name = request.form.get('name')
    if not name:
        flash('Department Name cannot be empty.', 'danger')
    else:
        department.name = name
        department.description = request.form.get('description')
        department.is_active = 'is_active' in request.form
        db.session.commit()
        flash(f'Department "{department.name}" updated successfully.', 'success')
    return redirect(url_for('manage_departments'))

@app.route('/departments/delete/<int:dept_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_DEPARTMENTS')
def delete_department(dept_id):
    department = Department.query.get_or_404(dept_id)
    if department.company_id != current_user.company_id:
        abort(403)
    
    # Future-proofing: check if department is in use by users/teams
    # if department.users:
    #     flash('Cannot delete department as it is in use.', 'danger')
    # else:
    db.session.delete(department)
    db.session.commit()
    flash(f'Department "{department.name}" has been deleted.', 'success')
        
    return redirect(url_for('manage_departments'))

# --- LOCATION MANAGEMENT ROUTES ---

@app.route('/locations')
@login_required
@permission_required('CAN_MANAGE_LOCATIONS')
def manage_locations():
    search_query = request.args.get('q', '').strip()
    query = Location.query.filter(Location.company_id == current_user.company_id)
    if search_query:
        query = query.filter(Location.name.ilike(f'%{search_query}%'))
    
    # In the future, you can add user/equipment counts here
    locations = query.order_by(Location.name).all()
    
    return render_template(
        'locations/index.html',
        locations=locations,
        search_query=search_query
    )

@app.route('/locations/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_LOCATIONS')
def add_location():
    if request.method == 'POST':
        new_location = Location(
            company_id=current_user.company_id,
            name=request.form.get('name'),
            address=request.form.get('address'),
            country=request.form.get('country'),
            state=request.form.get('state'),
            city=request.form.get('city'),
            zip_code=request.form.get('zip_code'),
            description=request.form.get('description'),
            contact_person=request.form.get('contact_person'),
            contact_phone=request.form.get('contact_phone'),
            contact_email=request.form.get('contact_email'),
            latitude=request.form.get('latitude') or None,
            longitude=request.form.get('longitude') or None,
            is_active=True
        )
        db.session.add(new_location)
        db.session.commit()
        flash(f'Location "{new_location.name}" created successfully.', 'success')
        return redirect(url_for('manage_locations'))
    
    return render_template('locations/form.html', location=None, maps_api_key=os.getenv('GOOGLE_MAPS_API_KEY'))

@app.route('/locations/edit/<int:loc_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_LOCATIONS')
def edit_location(loc_id):
    location = Location.query.get_or_404(loc_id)
    if location.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        location.name = request.form.get('name')
        location.address = request.form.get('address')
        location.country = request.form.get('country')
        location.state = request.form.get('state')
        location.city = request.form.get('city')
        location.zip_code = request.form.get('zip_code')
        location.description = request.form.get('description')
        location.contact_person = request.form.get('contact_person')
        location.contact_phone = request.form.get('contact_phone')
        location.contact_email = request.form.get('contact_email')
        location.latitude = request.form.get('latitude') or None
        location.longitude = request.form.get('longitude') or None
        location.is_active = 'is_active' in request.form
        db.session.commit()
        flash(f'Location "{location.name}" updated successfully.', 'success')
        return redirect(url_for('manage_locations'))

    return render_template('locations/form.html', location=location, maps_api_key=os.getenv('GOOGLE_MAPS_API_KEY'))

@app.route('/locations/delete/<int:loc_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_LOCATIONS')
def delete_location(loc_id):
    location = Location.query.get_or_404(loc_id)
    if location.company_id != current_user.company_id:
        abort(403)
    
    # Future-proofing: check for associated users/equipment
    db.session.delete(location)
    db.session.commit()
    flash(f'Location "{location.name}" has been deleted.', 'success')
    return redirect(url_for('manage_locations'))

# --- EQUIPMENT MANAGEMENT ROUTES ---

def get_form_data():
    """Helper to fetch data for the equipment form dropdowns."""
    company_id = current_user.company_id
    return {
        'categories': Category.query.filter_by(company_id=company_id, is_active=True).all(),
        'locations': Location.query.filter_by(company_id=company_id, is_active=True).all(),
        'departments': Department.query.filter_by(company_id=company_id, is_active=True).all(),
        'vendors': Vendor.query.filter_by(company_id=company_id).order_by(Vendor.name).all() # <-- ADD THIS LINE
    }

@app.route('/equipment')
@login_required
@permission_required('CAN_MANAGE_EQUIPMENT')
def manage_equipment():
    search_query = request.args.get('q', '').strip()
    
    # Base query for the user's company
    query = Equipment.query.filter(Equipment.company_id == current_user.company_id)
    
    # Eagerly load related models to prevent N+1 query problem
    # This fetches all related data in one go, which is very efficient.
    query = query.options(
        joinedload(Equipment.category),
        joinedload(Equipment.location),
        joinedload(Equipment.department)
    )

    if search_query:
        # Search across multiple relevant fields
        search_term = f"%{search_query}%"
        query = query.filter(
            db.or_(
                Equipment.name.ilike(search_term),
                Equipment.equipment_id.ilike(search_term),
                Category.name.ilike(search_term) # Also search in category name
            )
        )

    equipment_list = query.order_by(Equipment.name).all()
    
    return render_template(
        'equipment/index.html',
        equipment_list=equipment_list,
        search_query=search_query
    )

@app.route('/equipment/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_ADD_EQUIPMENT')
def add_equipment():
    if request.method == 'POST':
        # --- Form Data Validation ---
        name = request.form.get('name')
        category_id = request.form.get('category_id')

        if not name or not category_id:
            flash('Equipment Name and Category are required fields.', 'danger')
            return render_template('equipment/form.html', form_data=get_form_data(), equipment=None)

        # Create the initial Equipment object without file data
        new_equip = Equipment(
            company_id=current_user.company_id,
            name=name,
            equipment_id=request.form.get('equipment_id'),
            category_id=category_id,
            criticality=request.form.get('criticality'),
            manufacturer_id=request.form.get('manufacturer_id') or None,
            model=request.form.get('model'),
            serial_number=request.form.get('serial_number'),
            purchase_date=request.form.get('purchase_date') or None,
            warranty_expiry_date=request.form.get('warranty_expiry_date') or None,
            location_id=request.form.get('location_id') or None,
            department_id=request.form.get('department_id') or None,
            description=request.form.get('description'),
            specifications=request.form.get('specifications')
        )
        
        db.session.add(new_equip)
        save_actions = []  # Initialize an empty list to hold file saving functions

        try:
            # Flush the session to assign an ID to new_equip.
            # This ID is crucial for creating unique filenames.
            db.session.flush()
            
            # This now returns TWO values: filenames for the DB, and actions to run on success
            saved_files, save_actions = process_uploads(new_equip, request.files, 'equipment')
            
            # Update the object with the lists of filenames (or None if empty)
            new_equip.images = saved_files['images'] or []
            new_equip.videos = saved_files['videos'] or []
            new_equip.audio_files = saved_files['audio_files'] or []
            new_equip.documents = saved_files['documents'] or []

            # --- Transactional Step 1: Commit to Database ---
            # If this fails, the 'except' block will be triggered and no files will be saved.
            db.session.commit()
            
            # --- Transactional Step 2: Save Files to Disk ---
            # This code only runs if the database commit was successful.
            for file, save_path in save_actions:
                file.save(save_path)
            
            flash(f'Equipment "{new_equip.name}" created successfully.', 'success')
        
        except Exception as e:
            # If any part of the process fails, roll back the database transaction
            db.session.rollback()
            flash(f'An error occurred while creating the equipment: {e}', 'danger')
            # For debugging, you might want to log the full error `e`
            print(f"Error in add_equipment: {e}")
        
        return redirect(url_for('manage_equipment'))

    # For a GET request, just show the blank form
    return render_template('equipment/form.html', form_data=get_form_data(), equipment=None)

@app.route('/equipment/view/<int:equip_id>')
@login_required
@permission_required('CAN_VIEW_EQUIPMENT') # Or a new 'CAN_VIEW_EQUIPMENT' permission if you prefer
def view_equipment(equip_id):
    equipment = Equipment.query.options(
        joinedload(Equipment.category),
        joinedload(Equipment.location),
        joinedload(Equipment.department)
    ).get_or_404(equip_id)

    # Security check
    if equipment.company_id != current_user.company_id:
        abort(403)

    return render_template('equipment/view.html', equipment=equipment)

@app.route('/equipment/edit/<int:equip_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_EDIT_EQUIPMENT')
def edit_equipment(equip_id):
    equipment = Equipment.query.get_or_404(equip_id)
    if equipment.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        save_actions = [] # Initialize here
        try:
            # --- 1. Update text-based fields ---
            equipment.name = request.form.get('name')
            equipment.equipment_id = request.form.get('equipment_id')
            equipment.category_id = request.form.get('category_id')
            equipment.criticality = request.form.get('criticality')
            equipment.manufacturer_id = request.form.get('manufacturer_id') or None
            equipment.model = request.form.get('model')
            equipment.serial_number = request.form.get('serial_number')
            purchase_str = request.form.get('purchase_date')
            equipment.purchase_date = datetime.strptime(purchase_str, '%Y-%m-%d').date() if purchase_str else None
            warranty_str = request.form.get('warranty_expiry_date')
            equipment.warranty_expiry_date = datetime.strptime(warranty_str, '%Y-%m-%d').date() if warranty_str else None
            equipment.location_id = request.form.get('location_id') or None
            equipment.department_id = request.form.get('department_id') or None
            equipment.description = request.form.get('description')
            equipment.specifications = request.form.get('specifications')
            
            # --- 2. Handle new file uploads ---
            # Call the generic helper and unpack BOTH return values
            newly_saved_files, save_actions = process_uploads(equipment, request.files, 'equipment')
            
            # Merge new filenames with existing ones
            if newly_saved_files['images']: equipment.images = (equipment.images or []) + newly_saved_files['images']
            if newly_saved_files['videos']: equipment.videos = (equipment.videos or []) + newly_saved_files['videos']
            if newly_saved_files['audio_files']: equipment.audio_files = (equipment.audio_files or []) + newly_saved_files['audio_files']
            if newly_saved_files['documents']: equipment.documents = (equipment.documents or []) + newly_saved_files['documents']
            
            # Flag the JSONB fields as modified
            flag_modified(equipment, "images")
            flag_modified(equipment, "videos")
            flag_modified(equipment, "audio_files")
            flag_modified(equipment, "documents")

            # --- 3. Commit DB changes, then save files ---
            db.session.commit()
            for file, save_path in save_actions:
                file.save(save_path)
                
            flash(f'Equipment "{equipment.name}" updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the equipment: {e}', 'danger')
            print(f"Error in edit_equipment: {e}") # For debugging

        return redirect(url_for('manage_equipment'))

    # For a GET request
    return render_template('equipment/form.html', equipment=equipment, form_data=get_form_data())

@app.route('/equipment/delete/<int:equip_id>', methods=['POST'])
@login_required
@permission_required('CAN_DELETE_EQUIPMENT')
def delete_equipment(equip_id):
    # Retrieve the equipment or return a 404 error if not found
    equipment = Equipment.query.get_or_404(equip_id)

    # --- Security Check ---
    # Ensure the user is deleting equipment that belongs to their own company
    if equipment.company_id != current_user.company_id:
        abort(403) # Forbidden

    # Future-proofing: You can add a check here to prevent deletion
    # if the equipment is part of an active, non-closed work order.
    # For example:
    # if WorkOrder.query.filter_by(equipment_id=equipment.id, status='Open').first():
    #     flash(f'Cannot delete "{equipment.name}" as it is linked to an open work order.', 'danger')
    #     return redirect(url_for('manage_equipment'))

    try:
        # --- Step 1: Delete associated files from the filesystem ---
        delete_all_uploads(equipment, 'equipment')

        # --- Step 2: Delete the record from the database ---
        db.session.delete(equipment)
        db.session.commit()
        
        flash(f'Equipment "{equipment.name}" and all associated media have been deleted.', 'success')

    except Exception as e:
        # If anything fails, roll back the database change
        db.session.rollback()
        flash(f'An error occurred while deleting the equipment: {e}', 'danger')
        # Consider logging the full error `e` here for debugging

    return redirect(url_for('manage_equipment'))

@app.route('/equipment/<int:equip_id>/delete-media', methods=['POST'])
@login_required
@permission_required('CAN_EDIT_EQUIPMENT')
def delete_equipment_media(equip_id):
    equipment = Equipment.query.get_or_404(equip_id)
    if equipment.company_id != current_user.company_id:
        abort(403)
        
    filename = request.form.get('filename')
    file_type_key = request.form.get('file_type') # This is the model attribute name (e.g., 'audio_files')
    
    if not all([filename, file_type_key]):
        flash('Missing file information for deletion.', 'danger')
        return redirect(url_for('edit_equipment', equip_id=equip_id))

    # --- THIS IS THE FIX ---
    # Map the attribute name to the correct folder name
    type_to_folder_map = {'images': 'images', 'videos': 'videos', 'audio_files': 'audio', 'documents': 'documents'}
    folder_name = type_to_folder_map.get(file_type_key)

    if not folder_name:
        flash('Invalid file type specified.', 'danger')
        return redirect(url_for('edit_equipment', equip_id=equip_id))

    current_files = getattr(equipment, file_type_key, [])
    
    if filename in current_files:
        # Step 1: Delete the physical file using the correct folder name
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'equipment', folder_name, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Step 2: Remove from database list
        current_files.remove(filename)
        setattr(equipment, file_type_key, current_files or None) # Set to None if list becomes empty
        
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(equipment, file_type_key)
        
        db.session.commit()
        flash(f'File "{filename.split("_")[-1]}" deleted successfully.', 'success')
    else:
        flash('File not found for this equipment.', 'warning')
        
    return redirect(url_for('edit_equipment', equip_id=equip_id))

@app.route('/equipment/qr-code/<int:equip_id>')
@login_required
@permission_required('CAN_VIEW_EQUIPMENT') # Or a more specific permission
def generate_qr_code(equip_id):
    equipment = Equipment.query.options(
        joinedload(Equipment.location),
        joinedload(Equipment.category)
    ).get_or_404(equip_id)
    
    # Security check
    if equipment.company_id != current_user.company_id:
        abort(403)

    # --- 1. Generate the URL the QR code will point to ---
    # _external=True is crucial to get the full domain name
    qr_url = url_for('report_failure', equip_id=equipment.id, _external=True)

    # --- 2. Generate the QR code image in memory ---
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # --- 3. Convert image to a Data URI for embedding in HTML ---
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    qr_img_data_uri = f"data:image/png;base64,{img_str}"
    
    return render_template(
        'equipment/generate_qr.html', 
        equipment=equipment,
        qr_url=qr_url,
        qr_img=qr_img_data_uri
    )

# --- PUBLIC FAILURE REPORT ROUTE ---

@app.route('/report-failure/<int:equip_id>', methods=['GET', 'POST'])
def report_failure(equip_id):
    # This page is public; no @login_required.
    # We eager-load all data the form might need for display.
    equipment = Equipment.query.options(
        joinedload(Equipment.location),
        joinedload(Equipment.category),
        joinedload(Equipment.department)
    ).get_or_404(equip_id)

    if request.method == 'POST':
        # --- 1. Find or Create the generic "System Reporter" user for this company ---
        system_reporter_username = f"system_reporter_{equipment.company_id}"
        system_reporter = User.query.filter_by(
            company_id=equipment.company_id, 
            username=system_reporter_username
        ).first()
        
        if not system_reporter:
            print(f"System reporter not found for company {equipment.company_id}. Creating one now.")
            system_reporter = User(
                company_id=equipment.company_id, username=system_reporter_username,
                email=f"{system_reporter_username}@internal.maintaindesk.com",
                first_name="System", last_name="Reporter", is_active=False
            )
            system_reporter.set_password(uuid.uuid4().hex)
            db.session.add(system_reporter)
            try:
                # We must commit here to get the user's ID for the foreign key
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"CRITICAL ERROR: Could not create system_reporter. Error: {e}")
                flash('A critical system configuration error occurred. Could not file report.', 'danger')
                return render_template('public/report_failure.html', equipment=equipment, hide_sidebar=True)

        # --- 2. Create the Work Order with "On Hold" status and guest info ---
        new_wo = WorkOrder(
            company_id=equipment.company_id,
            title=request.form.get('title'),
            description=request.form.get('description'),
            priority=request.form.get('priority', 'Urgent'),
            work_order_type='Corrective',
            equipment_id=equipment.id,
            location_id=equipment.location_id,
            created_by_id=system_reporter.id,
            status='On Hold',
            is_approved=False,
            guest_reporter_name=request.form.get('guest_name', '').strip() or None,
            guest_reporter_email=request.form.get('guest_email', '').strip() or None
        )
        
        db.session.add(new_wo)
        save_actions = []
        try:
            db.session.flush() # Get the new_wo.id for file naming
            
            saved_files, save_actions = process_uploads(new_wo, request.files, 'work_orders')
            new_wo.images = saved_files['images'] or []
            new_wo.videos = saved_files['videos'] or []
            new_wo.audio_files = saved_files['audio_files'] or []
            new_wo.documents = saved_files['documents'] or []
            
            db.session.commit()
            for file, path in save_actions:
                file.save(path)
            
            # --- 3. Notify Approvers ---
            send_approval_request_email(new_wo)
            
            flash('Thank you! Your failure report has been successfully submitted for review.', 'success')
            return redirect(url_for('report_submitted', equip_id=equipment.id))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while submitting your report: {e}', 'danger')
            return render_template('public/report_failure.html', equipment=equipment, hide_sidebar=True)

    # For a GET request
    return render_template('public/report_failure.html', equipment=equipment, hide_sidebar=True)

@app.route('/report-submitted/<int:equip_id>')
def report_submitted(equip_id):
    """A simple 'Thank You' page after a successful submission."""
    equipment = Equipment.query.get_or_404(equip_id)
    return render_template('public/report_submitted.html', equipment=equipment, hide_sidebar=True)

# --- DATA API GETTER ROUTES ---

@app.route('/api/categories')
@login_required
def api_get_categories():
    categories = Category.query.filter_by(company_id=current_user.company_id, is_active=True).order_by(Category.name).all()
    # Convert SQLAlchemy objects to a list of dictionaries
    return jsonify([{'id': cat.id, 'name': cat.name} for cat in categories])

@app.route('/api/locations')
@login_required
def api_get_locations():
    locations = Location.query.filter_by(company_id=current_user.company_id, is_active=True).order_by(Location.name).all()
    return jsonify([{'id': loc.id, 'name': loc.name} for loc in locations])

@app.route('/api/departments')
@login_required
def api_get_departments():
    departments = Department.query.filter_by(company_id=current_user.company_id, is_active=True).order_by(Department.name).all()
    return jsonify([{'id': dept.id, 'name': dept.name} for dept in departments])

@app.route('/api/currencies')
@login_required
def api_get_currencies():
    currencies = Currency.query.filter_by(company_id=current_user.company_id, is_active=True).order_by(Currency.name).all()
    return jsonify([{'id': curr.id, 'name': curr.name, 'code': curr.code, 'symbol': curr.symbol} for curr in currencies])

@app.route('/api/units')
@login_required
def api_get_units():
    units = Unit.query.filter_by(company_id=current_user.company_id).order_by(Unit.name).all()
    # We include the symbol as it's useful for the dropdown text
    return jsonify([{'id': unit.id, 'name': unit.name, 'symbol': unit.symbol} for unit in units])

@app.route('/api/vendors')
@login_required
def api_get_vendors():
    vendors = Vendor.query.filter_by(company_id=current_user.company_id).order_by(Vendor.name).all()
    return jsonify([{'id': v.id, 'name': v.name} for v in vendors])

@app.route('/api/equipment')
@login_required
def api_get_equipment():
    equipment_list = Equipment.query.filter_by(company_id=current_user.company_id).order_by(Equipment.name).all()
    # Return a list of simple objects with id and name
    return jsonify([{'id': eq.id, 'name': eq.name} for eq in equipment_list])

@app.route('/api/technicians')
@login_required
def api_get_technicians():
    # A "technician" is any non-admin user
    technicians = User.query.join(Role).filter(
        User.company_id == current_user.company_id,
        Role.is_admin == False,
        User.is_active == True
    ).order_by(User.first_name).all()
    # Return a list with id and full name
    return jsonify([{'id': tech.id, 'name': f"{tech.first_name} {tech.last_name}"} for tech in technicians])

@app.route('/api/teams')
@login_required
def api_get_teams():
    teams = Team.query.filter_by(company_id=current_user.company_id, is_active=True).order_by(Team.name).all()
    return jsonify([{'id': team.id, 'name': team.name} for team in teams])

# --- DATA API ROUTES ---

@app.route('/api/locations/countries')
@login_required
def get_countries():
    """Returns a JSON list of all countries."""
    countries = [{'code': country.alpha_2, 'name': country.name} for country in pycountry.countries]
    return jsonify(sorted(countries, key=lambda x: x['name']))

@app.route('/api/locations/states/<country_code>')
@login_required
def get_states(country_code):
    """Returns a JSON list of states for a given country code."""
    try:
        states = [{'code': state.code, 'name': state.name} for state in pycountry.subdivisions.get(country_code=country_code)]
        return jsonify(sorted(states, key=lambda x: x['name']))
    except KeyError:
        return jsonify([]) # Return empty list if country has no subdivisions
    
    
@app.route('/api/categories/add', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_CATEGORIES') # Reuse existing permission
def api_add_category():
    data = request.json
    new_category = Category(
        company_id=current_user.company_id,
        name=data.get('name'),
        category_type=data.get('type')
    )
    db.session.add(new_category)
    db.session.commit()
    return jsonify({'id': new_category.id, 'name': new_category.name}), 201

# Add similar API routes for Location and Department
@app.route('/api/locations/add', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_LOCATIONS')
def api_add_location():
    data = request.json
    new_loc = Location(company_id=current_user.company_id, name=data.get('name'))
    db.session.add(new_loc)
    db.session.commit()
    return jsonify({'id': new_loc.id, 'name': new_loc.name}), 201

@app.route('/api/departments/add', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_DEPARTMENTS')
def api_add_department():
    data = request.json
    new_dept = Department(company_id=current_user.company_id, name=data.get('name'))
    db.session.add(new_dept)
    db.session.commit()
    return jsonify({'id': new_dept.id, 'name': new_dept.name}), 201

@app.route('/roles/create', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_ROLES')
def create_role():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        # --- Validation ---
        if not name:
            flash('Role name is required.', 'danger')
            return redirect(url_for('create_role'))
        
        # Check for duplicate role name within the same company
        existing_role = Role.query.filter_by(company_id=current_user.company_id, name=name).first()
        if existing_role:
            flash(f'A role with the name "{name}" already exists.', 'warning')
            return redirect(url_for('create_role'))

        # --- Create New Role ---
        new_role = Role(
            name=name,
            description=description,
            company_id=current_user.company_id,
            is_admin=False  # Custom roles can never be the default Admin
        )
        
        # --- Assign Permissions ---
        selected_permission_ids = request.form.getlist('permissions')
        new_role.permissions = Permission.query.filter(Permission.id.in_(selected_permission_ids)).all()
        
        db.session.add(new_role)
        db.session.commit()
        
        flash(f'Successfully created the "{name}" role.', 'success')
        return redirect(url_for('manage_roles'))

    all_permissions = Permission.query.all()
    return render_template('roles/create_role.html', all_permissions=all_permissions)

@app.route('/roles/delete/<int:role_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_ROLES')
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)

    # --- Security & Integrity Checks ---

    # 1. Ensure role belongs to the user's company
    if role.company_id != current_user.company_id:
        abort(403)

    # 2. Prevent deletion of default system roles
    default_roles = ['Admin', 'Manager', 'Technician', 'Viewer']
    if role.name in default_roles:
        flash(f'The default role "{role.name}" cannot be deleted.', 'danger')
        return redirect(url_for('manage_roles'))

    # 3. Prevent deletion if the role is assigned to any users
    if role.users:
        flash(f'Cannot delete "{role.name}" because it is currently assigned to one or more users.', 'warning')
        return redirect(url_for('manage_roles'))

    # --- Perform Deletion ---
    try:
        db.session.delete(role)
        db.session.commit()
        flash(f'Successfully deleted the role "{role.name}".', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while trying to delete the role.', 'danger')
        # You might want to log the error `e` here
    
    return redirect(url_for('manage_roles'))

# --- UNIT & MEASUREMENT ROUTES ---

@app.route('/units')
@login_required
@permission_required('CAN_MANAGE_UNITS')
def manage_units():
    search_query = request.args.get('q', '').strip()
    
    # Use an alias for the self-join to get the base unit's name
    BaseUnit = aliased(Unit)
    query = db.session.query(Unit, BaseUnit.name.label('base_unit_name')).outerjoin(
        BaseUnit, Unit.base_unit_id == BaseUnit.id
    ).filter(Unit.company_id == current_user.company_id)

    if search_query:
        query = query.filter(Unit.name.ilike(f'%{search_query}%'))
        
    units = query.order_by(Unit.name).all()
    
    # Get all units for the "Relative Unit" dropdown in the modal
    all_units = Unit.query.filter_by(company_id=current_user.company_id).order_by(Unit.name).all()
    
    return render_template(
        'units/index.html',
        units=units,
        all_units=all_units, # Pass this for the modal dropdown
        search_query=search_query
    )

@app.route('/api/unit/<int:unit_id>')
@login_required
def api_get_unit(unit_id):
    """API endpoint to get a single unit's data for the edit modal."""
    unit = Unit.query.get_or_404(unit_id)
    if unit.company_id != current_user.company_id:
        abort(403)
    return jsonify({
        'id': unit.id,
        'name': unit.name,
        'symbol': unit.symbol,
        'base_unit_id': unit.base_unit_id,
        'conversion_factor': unit.conversion_factor
    })

@app.route('/units/add', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_UNITS')
def add_unit():
    name = request.form.get('name')
    if not name:
        flash('Unit Name is required.', 'danger')
    else:
        new_unit = Unit(
            company_id=current_user.company_id,
            name=name,
            symbol=request.form.get('symbol'),
            base_unit_id=request.form.get('base_unit_id') or None,
            conversion_factor=request.form.get('conversion_factor') or None
        )
        db.session.add(new_unit)
        db.session.commit()
        flash(f'Unit "{name}" created successfully.', 'success')
    return redirect(url_for('manage_units'))

@app.route('/units/edit/<int:unit_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_UNITS')
def edit_unit(unit_id):
    unit = Unit.query.get_or_404(unit_id)
    if unit.company_id != current_user.company_id:
        abort(403)
    
    name = request.form.get('name')
    if not name:
        flash('Unit Name cannot be empty.', 'danger')
    else:
        unit.name = name
        unit.symbol = request.form.get('symbol')
        unit.base_unit_id = request.form.get('base_unit_id') or None
        unit.conversion_factor = request.form.get('conversion_factor') or None
        db.session.commit()
        flash(f'Unit "{unit.name}" updated successfully.', 'success')
    return redirect(url_for('manage_units'))

@app.route('/units/delete/<int:unit_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_UNITS')
def delete_unit(unit_id):
    unit = Unit.query.get_or_404(unit_id)
    if unit.company_id != current_user.company_id:
        abort(403)
    
    # Prevent deletion if it's a base for other units
    if unit.derived_units:
        flash(f'Cannot delete "{unit.name}" as it is a base unit for other units.', 'danger')
    else:
        db.session.delete(unit)
        db.session.commit()
        flash(f'Unit "{unit.name}" has been deleted.', 'success')
        
    return redirect(url_for('manage_units'))

# --- CURRENCY MANAGEMENT ROUTES ---

@app.route('/currencies')
@login_required
@permission_required('CAN_MANAGE_CURRENCIES')
def manage_currencies():
    search_query = request.args.get('q', '').strip()
    query = Currency.query.filter(Currency.company_id == current_user.company_id)
    if search_query:
        query = query.filter(db.or_(
            Currency.name.ilike(f'%{search_query}%'),
            Currency.code.ilike(f'%{search_query}%')
        ))
    currencies = query.order_by(Currency.name).all()
    return render_template(
        'currencies/index.html',
        currencies=currencies,
        search_query=search_query
    )

@app.route('/api/currency/<int:currency_id>')
@login_required
def api_get_currency(currency_id):
    currency = Currency.query.get_or_404(currency_id)
    if currency.company_id != current_user.company_id:
        abort(403)
    return jsonify({
        'id': currency.id,
        'name': currency.name,
        'code': currency.code,
        'symbol': currency.symbol
    })

@app.route('/currencies/add', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_CURRENCIES')
def add_currency():
    name = request.form.get('name')
    code = request.form.get('code')
    if not name or not code:
        flash('Currency Name and Code are required.', 'danger')
    else:
        new_curr = Currency(
            company_id=current_user.company_id,
            name=name,
            code=code.upper(),
            symbol=request.form.get('symbol')
        )
        db.session.add(new_curr)
        db.session.commit()
        flash(f'Currency "{name}" created successfully.', 'success')
    return redirect(url_for('manage_currencies'))

@app.route('/currencies/edit/<int:currency_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_CURRENCIES')
def edit_currency(currency_id):
    currency = Currency.query.get_or_404(currency_id)
    if currency.company_id != current_user.company_id:
        abort(403)
    
    name = request.form.get('name')
    code = request.form.get('code')
    if not name or not code:
        flash('Currency Name and Code cannot be empty.', 'danger')
    else:
        currency.name = name
        currency.code = code.upper()
        currency.symbol = request.form.get('symbol')
        db.session.commit()
        flash(f'Currency "{currency.name}" updated successfully.', 'success')
    return redirect(url_for('manage_currencies'))

@app.route('/currencies/delete/<int:currency_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_CURRENCIES')
def delete_currency(currency_id):
    currency = Currency.query.get_or_404(currency_id)
    if currency.company_id != current_user.company_id:
        abort(403)
    
    # Future-proofing: prevent deletion if currency is in use
    # if currency.purchase_orders: ...
    
    db.session.delete(currency)
    db.session.commit()
    flash(f'Currency "{currency.name}" has been deleted.', 'success')
        
    return redirect(url_for('manage_currencies'))

@app.route('/currencies/set-default/<int:currency_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_CURRENCIES')
def set_default_currency(currency_id):
    currency_to_set = Currency.query.get_or_404(currency_id)
    if currency_to_set.company_id != current_user.company_id:
        abort(403)

    # Find the current default and unset it
    current_default = Currency.query.filter_by(company_id=current_user.company_id, is_default=True).first()
    if current_default:
        current_default.is_default = False

    # Set the new default
    currency_to_set.is_default = True
    db.session.commit()
    
    flash(f'"{currency_to_set.name}" is now the default currency.', 'success')
    return redirect(url_for('manage_currencies'))

# --- INVENTORY MANAGEMENT ROUTES ---

def get_inventory_form_data():
    """Helper to fetch data for the inventory form dropdowns."""
    company_id = current_user.company_id
    default_currency = Currency.query.filter_by(company_id=company_id, is_default=True).first()
    return {
        'categories': Category.query.filter_by(company_id=company_id, is_active=True, category_type='Inventory').order_by(Category.name).all(),
        'departments': Department.query.filter_by(company_id=company_id, is_active=True).order_by(Department.name).all(),
        'currencies': Currency.query.filter_by(company_id=company_id, is_active=True).order_by(Currency.name).all(),
        'units': Unit.query.filter_by(company_id=company_id).order_by(Unit.name).all(),
        'locations': Location.query.filter_by(company_id=company_id, is_active=True).order_by(Location.name).all(),
        'vendors': Vendor.query.filter_by(company_id=company_id).order_by(Vendor.name).all(), # <-- ADD THIS LINE
        'default_currency_id': default_currency.id if default_currency else None
    }

@app.route('/inventory')
@login_required
@permission_required('CAN_MANAGE_INVENTORY')
def manage_inventory():
    search_query = request.args.get('q', '').strip()
    query = InventoryItem.query.filter(InventoryItem.company_id == current_user.company_id)
    query = query.options(
        joinedload(InventoryItem.category),
        joinedload(InventoryItem.location)
    )
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(
            db.or_(
                InventoryItem.name.ilike(search_term),
                InventoryItem.part_number.ilike(search_term),
                Category.name.ilike(search_term)
            )
        )
    inventory_list = query.order_by(InventoryItem.name).all()
    return render_template(
        'inventory/index.html',
        inventory_list=inventory_list,
        search_query=search_query
    )

@app.route('/inventory/view/<int:item_id>')
@login_required
@permission_required('CAN_VIEW_INVENTORY')
def view_inventory_item(item_id):
    # Eagerly load all related data, including the direct manufacturer and supplier relationships
    item = InventoryItem.query.options(
        joinedload(InventoryItem.category),
        joinedload(InventoryItem.location),
        joinedload(InventoryItem.department),
        joinedload(InventoryItem.currency),
        joinedload(InventoryItem.unit_of_measure),
        joinedload(InventoryItem.manufacturer),
        joinedload(InventoryItem.supplier)
    ).get_or_404(item_id)

    # Security check
    if item.company_id != current_user.company_id:
        abort(403)

    # The old logic for finding manufacturer/supplier is no longer needed.
    # We now pass the entire 'item' object, which contains the relationships.
    return render_template('inventory/view.html', item=item)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_ADD_INVENTORY')
def add_inventory_item():
    if request.method == 'POST':
        if not all([request.form.get('name'), request.form.get('category_id'), request.form.get('minimum_stock')]):
            flash('Item Name, Category, and Minimum Stock are required.', 'danger')
            return render_template('inventory/form.html', form_data=get_inventory_form_data(), item=None)

        new_item = InventoryItem(
            company_id=current_user.company_id,
            name=request.form.get('name'),
            part_number=request.form.get('part_number'),
            category_id=request.form.get('category_id'),
            department_id=request.form.get('department_id') or None,
            description=request.form.get('description'),
            manufacturer_id=request.form.get('manufacturer_id') or None,
            supplier_id=request.form.get('supplier_id') or None,
            unit_cost=request.form.get('unit_cost') or None,
            currency_id=request.form.get('currency_id') or None,
            unit_of_measure_id=request.form.get('unit_of_measure_id') or None,
            current_stock=request.form.get('current_stock') or 0,
            minimum_stock=request.form.get('minimum_stock'),
            maximum_stock=request.form.get('maximum_stock') or None,
            location_id=request.form.get('location_id') or None
        )
        db.session.add(new_item)
        save_actions = []
        try:
            db.session.flush()
            saved_files, save_actions = process_uploads(new_item, request.files, 'inventory')
            new_item.images = saved_files['images'] or []
            new_item.videos = saved_files['videos'] or []
            new_item.audio_files = saved_files['audio_files'] or []
            new_item.documents = saved_files['documents'] or []
            db.session.commit()
            for file, save_path in save_actions:
                file.save(save_path)
            flash(f'Inventory item "{new_item.name}" created successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the item: {e}', 'danger')
        
        return redirect(url_for('manage_inventory'))
    
    return render_template('inventory/form.html', form_data=get_inventory_form_data(), item=None)

@app.route('/inventory/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_EDIT_INVENTORY')
def edit_inventory_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        save_actions = []
        try:
            item.name = request.form.get('name')
            item.part_number = request.form.get('part_number')
            item.category_id = request.form.get('category_id')
            item.department_id = request.form.get('department_id') or None
            item.description = request.form.get('description')
            item.manufacturer_id = request.form.get('manufacturer_id') or None
            item.supplier_id = request.form.get('supplier_id') or None
            item.unit_cost = request.form.get('unit_cost') or None
            item.currency_id = request.form.get('currency_id') or None
            item.unit_of_measure_id = request.form.get('unit_of_measure_id') or None
            item.current_stock = request.form.get('current_stock') or 0
            item.minimum_stock = request.form.get('minimum_stock')
            item.maximum_stock = request.form.get('maximum_stock') or None
            item.location_id = request.form.get('location_id') or None

            # --- Handle Media Uploads ---
            saved_files, save_actions = process_uploads(item, request.files, 'inventory')
            if saved_files['images']: item.images = (item.images or []) + saved_files['images']
            if saved_files['videos']: item.videos = (item.videos or []) + saved_files['videos']
            if saved_files['audio_files']: item.audio_files = (item.audio_files or []) + saved_files['audio_files']
            if saved_files['documents']: item.documents = (item.documents or []) + saved_files['documents']
            
            flag_modified(item, "images")
            flag_modified(item, "videos")
            flag_modified(item, "audio_files")
            flag_modified(item, "documents")

            db.session.commit()
            for file, save_path in save_actions:
                file.save(save_path)
            
            flash(f'Item "{item.name}" updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the item: {e}', 'danger')

        return redirect(url_for('manage_inventory'))

    return render_template('inventory/form.html', form_data=get_inventory_form_data(), item=item)


@app.route('/inventory/delete/<int:item_id>', methods=['POST'])
@login_required
@permission_required('CAN_DELETE_INVENTORY')
def delete_inventory_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.company_id != current_user.company_id:
        abort(403)

    try:
        # --- Use Generic Helper to Delete Files ---
        delete_all_uploads(item, 'inventory')
        
        db.session.delete(item)
        db.session.commit()
        flash(f'Inventory item "{item.name}" and all associated media have been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the item: {e}', 'danger')

    return redirect(url_for('manage_inventory'))

@app.route('/inventory/<int:item_id>/delete-media', methods=['POST'])
@login_required
@permission_required('CAN_EDIT_INVENTORY')
def delete_inventory_media(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if item.company_id != current_user.company_id:
        abort(403)
        
    filename = request.form.get('filename')
    file_type_key = request.form.get('file_type')
    
    if not all([filename, file_type_key]):
        flash('Missing file information for deletion.', 'danger')
        return redirect(url_for('edit_inventory_item', item_id=item_id))

    # Map attribute name to folder name
    folder_map = {'images': 'images', 'videos': 'videos', 'audio_files': 'audio', 'documents': 'documents'}
    folder_name = folder_map.get(file_type_key)

    if not folder_name:
        flash('Invalid file type specified.', 'danger')
        return redirect(url_for('edit_inventory_item', item_id=item_id))

    current_files = getattr(item, file_type_key, [])
    
    if filename in current_files:
        # Delete physical file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'inventory', folder_name, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Remove from database list
        current_files.remove(filename)
        setattr(item, file_type_key, current_files or None)
        
        flag_modified(item, file_type_key)
        
        db.session.commit()
        flash(f'File "{filename.split("_")[-1]}" deleted successfully.', 'success')
    else:
        flash('File not found for this item.', 'warning')
        
    return redirect(url_for('edit_inventory_item', item_id=item_id))

# --- VENDOR MANAGEMENT ROUTES ---

def get_vendor_form_data(vendor=None):
    company_id = current_user.company_id
    associated_equipment_ids = set()
    
    # NEW: Create sets for manufactured and supplied inventory
    manufactured_inventory_ids = set()
    supplied_inventory_ids = set()

    if vendor:
        associated_equipment_ids = {eq.id for eq in Equipment.query.filter_by(manufacturer_id=vendor.id).all()}
        manufactured_inventory_ids = {inv.id for inv in InventoryItem.query.filter_by(manufacturer_id=vendor.id).all()}
        supplied_inventory_ids = {inv.id for inv in InventoryItem.query.filter_by(supplier_id=vendor.id).all()}

    return {
        'locations': Location.query.filter_by(company_id=company_id, is_active=True).order_by(Location.name).all(),
        'all_equipment': Equipment.query.filter_by(company_id=company_id).order_by(Equipment.name).all(),
        'all_inventory': InventoryItem.query.filter_by(company_id=company_id).order_by(InventoryItem.name).all(),
        'associated_equipment_ids': associated_equipment_ids,
        'manufactured_inventory_ids': manufactured_inventory_ids,
        'supplied_inventory_ids': supplied_inventory_ids,
    }

@app.route('/vendors')
@login_required
@permission_required('CAN_MANAGE_VENDORS')
def manage_vendors():
    search_query = request.args.get('q', '').strip()
    
    # Helper function to safely get JSONB array length
    def safe_jsonb_length(column):
        return case(
            (func.jsonb_typeof(column) == 'array', func.jsonb_array_length(column)),
            else_=0
        )
    
    query = db.session.query(
        Vendor,
        func.count(db.distinct(VendorContact.id)).label('contact_count'),
        (
            safe_jsonb_length(Vendor.images) +
            safe_jsonb_length(Vendor.videos) +
            safe_jsonb_length(Vendor.audio_files) +
            safe_jsonb_length(Vendor.documents)
        ).label('file_count')
    ).outerjoin(Vendor.contacts).outerjoin(Vendor.location)
   
    query = query.filter(Vendor.company_id == current_user.company_id)
    
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(
            db.or_(
                Vendor.name.ilike(search_term),
                Location.name.ilike(search_term)
            )
        )
   
    query = query.group_by(Vendor.id, Location.id)
    vendors_with_counts = query.order_by(Vendor.name).all()
   
    return render_template(
        'vendors/index.html',
        vendors_with_counts=vendors_with_counts,
        search_query=search_query
    )
    
@app.route('/vendors/view/<int:vendor_id>')
@login_required
@permission_required('CAN_VIEW_VENDORS')
def view_vendor(vendor_id):
    # Eagerly load the relationships that still exist on the Vendor model
    vendor = Vendor.query.options(
        joinedload(Vendor.location),
        joinedload(Vendor.contacts)
    ).get_or_404(vendor_id)

    # Security check
    if vendor.company_id != current_user.company_id:
        abort(403)

    # --- NEW LOGIC: Query for associated items separately ---
    associated_equipment = Equipment.query.filter_by(manufacturer_id=vendor.id).all()
    
    # Find inventory where this vendor is either the manufacturer OR the supplier
    associated_inventory = InventoryItem.query.filter(
        db.or_(
            InventoryItem.manufacturer_id == vendor.id,
            InventoryItem.supplier_id == vendor.id
        )
    ).all()
    # --- END OF NEW LOGIC ---

    return render_template(
        'vendors/view.html', 
        vendor=vendor, 
        associated_equipment=associated_equipment,
        associated_inventory=associated_inventory # Pass the new list to the template
    )

@app.route('/vendors/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_ADD_VENDORS')
def add_vendor():
    if request.method == 'POST':
        # --- 1. Basic Validation ---
        if not request.form.get('name'):
            flash('Vendor Name is a required field.', 'danger')
            return render_template('vendors/form.html', form_data=get_vendor_form_data(), vendor=None)

        # --- 2. Create Vendor and Basic Info ---
        new_vendor = Vendor(
            company_id=current_user.company_id,
            name=request.form.get('name'),
            description=request.form.get('description'),
            location_id=request.form.get('location_id') or None
        )
        
        # --- 3. Create and Add Dynamic Contacts ---
        contact_names = request.form.getlist('contact_name[]')
        contact_emails = request.form.getlist('contact_email[]')
        contact_phones = request.form.getlist('contact_phone[]')
        contact_positions = request.form.getlist('contact_position[]')
        
        for i, name in enumerate(contact_names):
            if name:
                new_contact = VendorContact(
                    company_id=current_user.company_id,
                    name=name,
                    email=contact_emails[i],
                    phone=contact_phones[i],
                    position=contact_positions[i]
                )
                new_vendor.contacts.append(new_contact)

        # We must add and flush the vendor first to get its ID
        db.session.add(new_vendor)
        db.session.flush()

        save_actions = []
        try:
            # --- 4. Handle Associations (Corrected Logic) ---
            # Equipment (one-to-many)
            equipment_ids = request.form.getlist('equipment_ids')
            if equipment_ids:
                Equipment.query.filter(
                    Equipment.company_id == current_user.company_id,
                    Equipment.id.in_(equipment_ids)
                ).update({'manufacturer_id': new_vendor.id}, synchronize_session=False)

            # Inventory (two separate one-to-many relationships)
            mfr_inventory_ids = request.form.getlist('mfr_inventory_ids')
            if mfr_inventory_ids:
                InventoryItem.query.filter(
                    InventoryItem.company_id == current_user.company_id,
                    InventoryItem.id.in_(mfr_inventory_ids)
                ).update({'manufacturer_id': new_vendor.id}, synchronize_session=False)

            splr_inventory_ids = request.form.getlist('splr_inventory_ids')
            if splr_inventory_ids:
                InventoryItem.query.filter(
                    InventoryItem.company_id == current_user.company_id,
                    InventoryItem.id.in_(splr_inventory_ids)
                ).update({'supplier_id': new_vendor.id}, synchronize_session=False)

            # --- 5. Handle Media Uploads ---
            saved_files, save_actions = process_uploads(new_vendor, request.files, 'vendors')
            new_vendor.images = saved_files['images'] or []
            new_vendor.videos = saved_files['videos'] or []
            new_vendor.audio_files = saved_files['audio_files'] or []
            new_vendor.documents = saved_files['documents'] or []
            
            # --- 6. Commit and Save Files ---
            db.session.commit()
            for file, path in save_actions:
                file.save(path)

            flash(f'Vendor "{new_vendor.name}" created successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the vendor: {e}', 'danger')
            print(f"Error in add_vendor: {e}")
            
        return redirect(url_for('manage_vendors'))
    
    # For a GET request, just show the blank form
    return render_template('vendors/form.html', form_data=get_vendor_form_data(), vendor=None)

@app.route('/vendors/edit/<int:vendor_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_EDIT_VENDORS')
def edit_vendor(vendor_id):
    # Eagerly load contacts for the form to prevent N+1 queries
    vendor = Vendor.query.options(
        joinedload(Vendor.contacts)
    ).get_or_404(vendor_id)

    if vendor.company_id != current_user.company_id:
        abort(403)
    
    if request.method == 'POST':
        save_actions = []
        try:
            # --- 1. Update Basic Info ---
            vendor.name = request.form.get('name')
            vendor.description = request.form.get('description')
            vendor.location_id = request.form.get('location_id') or None
            
            # --- 2. Sync Contacts ---
            existing_contacts = {c.id: c for c in vendor.contacts}
            submitted_ids = [int(i) for i in request.form.getlist('contact_id[]') if i]
            
            # Delete contacts that were removed from the form
            for id_to_delete in set(existing_contacts.keys()) - set(submitted_ids):
                db.session.delete(existing_contacts[id_to_delete])
            
            # Update existing and add new contacts
            for i, name in enumerate(request.form.getlist('contact_name[]')):
                if name: # Only process rows with a name
                    contact_id = int(request.form.getlist('contact_id[]')[i] or 0)
                    if contact_id in existing_contacts: # Update existing contact
                        contact = existing_contacts[contact_id]
                        contact.name = name
                        contact.email = request.form.getlist('contact_email[]')[i]
                        contact.phone = request.form.getlist('contact_phone[]')[i]
                        contact.position = request.form.getlist('contact_position[]')[i]
                    else: # Add as a new contact
                        new_contact = VendorContact(
                            company_id=current_user.company_id, # <-- CRUCIAL SECURITY ADDITION
                            name=name,
                            email=request.form.getlist('contact_email[]')[i],
                            phone=request.form.getlist('contact_phone[]')[i],
                            position=request.form.getlist('contact_position[]')[i]
                        )
                        vendor.contacts.append(new_contact)

            # --- 3. Sync Associations (Corrected Logic) ---
            # Equipment (one-to-many on Equipment.manufacturer_id)
            submitted_equipment_ids = {int(id) for id in request.form.getlist('equipment_ids')}
            currently_linked_equipment = Equipment.query.filter_by(manufacturer_id=vendor.id, company_id=current_user.company_id).all()
            currently_linked_ids = {eq.id for eq in currently_linked_equipment}
            
            ids_to_unlink_eq = currently_linked_ids - submitted_equipment_ids
            if ids_to_unlink_eq:
                Equipment.query.filter(Equipment.company_id == current_user.company_id, Equipment.id.in_(ids_to_unlink_eq)).update({'manufacturer_id': None}, synchronize_session=False)

            ids_to_link_eq = submitted_equipment_ids - currently_linked_ids
            if ids_to_link_eq:
                Equipment.query.filter(Equipment.company_id == current_user.company_id, Equipment.id.in_(ids_to_link_eq)).update({'manufacturer_id': vendor.id}, synchronize_session=False)

            # Inventory (two separate one-to-many relationships)
            submitted_mfr_ids = {int(id) for id in request.form.getlist('mfr_inventory_ids')}
            submitted_splr_ids = {int(id) for id in request.form.getlist('splr_inventory_ids')}

            # Unlink Manufacturer associations that were unchecked
            InventoryItem.query.filter(InventoryItem.manufacturer_id == vendor.id, InventoryItem.company_id == current_user.company_id, ~InventoryItem.id.in_(submitted_mfr_ids)).update({'manufacturer_id': None}, synchronize_session=False)
            # Link newly checked Manufacturer associations
            InventoryItem.query.filter(InventoryItem.company_id == current_user.company_id, InventoryItem.id.in_(submitted_mfr_ids)).update({'manufacturer_id': vendor.id}, synchronize_session=False)
            
            # Unlink Supplier associations that were unchecked
            InventoryItem.query.filter(InventoryItem.supplier_id == vendor.id, InventoryItem.company_id == current_user.company_id, ~InventoryItem.id.in_(submitted_splr_ids)).update({'supplier_id': None}, synchronize_session=False)
            # Link newly checked Supplier associations
            InventoryItem.query.filter(InventoryItem.company_id == current_user.company_id, InventoryItem.id.in_(submitted_splr_ids)).update({'supplier_id': vendor.id}, synchronize_session=False)

            # --- 4. Handle New File Uploads ---
            saved_files, save_actions = process_uploads(vendor, request.files, 'vendors')
            if saved_files['images']: vendor.images = (vendor.images or []) + saved_files['images']
            if saved_files['videos']: vendor.videos = (vendor.videos or []) + saved_files['videos']
            if saved_files['audio_files']: vendor.audio_files = (vendor.audio_files or []) + saved_files['audio_files']
            if saved_files['documents']: vendor.documents = (vendor.documents or []) + saved_files['documents']
            flag_modified(vendor, "images"); flag_modified(vendor, "videos");
            flag_modified(vendor, "audio_files"); flag_modified(vendor, "documents");

            # --- 5. Commit and Save Files ---
            db.session.commit()
            for file, path in save_actions:
                file.save(path)

            flash(f'Vendor "{vendor.name}" updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the vendor: {e}', 'danger')
            print(f"Error in edit_vendor: {e}")

        return redirect(url_for('manage_vendors'))

    return render_template('vendors/form.html', form_data=get_vendor_form_data(vendor), vendor=vendor)


@app.route('/vendors/delete/<int:vendor_id>', methods=['POST'])
@login_required
@permission_required('CAN_DELETE_VENDORS')
def delete_vendor(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    if vendor.company_id != current_user.company_id:
        abort(403)
    
    delete_all_uploads(vendor, 'vendors')
    db.session.delete(vendor)
    db.session.commit()
    flash(f'Vendor "{vendor.name}" has been deleted.', 'success')
    return redirect(url_for('manage_vendors'))

@app.route('/vendors/<int:vendor_id>/delete-media', methods=['POST'])
@login_required
@permission_required('CAN_EDIT_VENDORS')
def delete_vendor_media(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    if vendor.company_id != current_user.company_id:
        abort(403)
        
    filename = request.form.get('filename')
    file_type_key = request.form.get('file_type')
    
    if not all([filename, file_type_key]):
        flash('Missing file information for deletion.', 'danger')
        return redirect(url_for('edit_vendor', vendor_id=vendor_id))

    folder_map = {'images': 'images', 'videos': 'videos', 'audio_files': 'audio', 'documents': 'documents'}
    folder_name = folder_map.get(file_type_key)

    if not folder_name:
        flash('Invalid file type specified.', 'danger')
        return redirect(url_for('edit_vendor', vendor_id=vendor_id))

    current_files = getattr(vendor, file_type_key, [])
    
    if filename in current_files:
        try:
            # Delete physical file from the 'vendors' upload folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'vendors', folder_name, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                
            # Remove from database list
            current_files.remove(filename)
            setattr(vendor, file_type_key, current_files or None)
            
            flag_modified(vendor, file_type_key)
            db.session.commit()
            
            flash(f'File "{filename.split("_")[-1]}" deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while deleting the file: {e}", 'danger')
    else:
        flash('File not found for this vendor.', 'warning')
        
    return redirect(url_for('edit_vendor', vendor_id=vendor_id))

    
# --- TEAM MANAGEMENT ROUTES ---

def get_team_form_data():
    """Helper to fetch data for the team form."""
    # Fetch all non-admin users for the current company to be added as members
    return {
        'all_users': User.query.join(Role).filter(
            User.company_id == current_user.company_id,
            Role.is_admin == False
        ).order_by(User.first_name).all()
    }

@app.route('/teams')
@login_required
@permission_required('CAN_MANAGE_TEAMS')
def manage_teams():
    search_query = request.args.get('q', '').strip()
    
    # Base query to get teams and count their members
    query = db.session.query(
        Team,
        func.count(team_members.c.user_id).label('member_count')
    ).outerjoin(team_members).group_by(Team.id)
    
    # Filter by the current user's company
    query = query.filter(Team.company_id == current_user.company_id)

    if search_query:
        query = query.filter(Team.name.ilike(f'%{search_query}%'))

    teams_with_counts = query.order_by(Team.name).all()
    
    return render_template(
        'teams/index.html',
        teams_with_counts=teams_with_counts,
        search_query=search_query
    )

@app.route('/teams/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_TEAMS')
def add_team():
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Team Name is a required field.', 'danger')
            return render_template('teams/form.html', form_data=get_team_form_data(), team=None)

        # Check for duplicate team name
        if Team.query.filter_by(company_id=current_user.company_id, name=name).first():
            flash(f'A team with the name "{name}" already exists.', 'warning')
            return render_template('teams/form.html', form_data=get_team_form_data(), team=None)

        new_team = Team(
            company_id=current_user.company_id,
            name=name,
            description=request.form.get('description'),
            is_active=True # Default to active
        )
        
        # Find and associate selected members
        member_ids = request.form.getlist('member_ids')
        if member_ids:
            # Query for the User objects and assign them to the relationship
            members = User.query.filter(User.id.in_(member_ids)).all()
            new_team.members = members
        
        db.session.add(new_team)
        db.session.commit()
        
        flash(f'Team "{new_team.name}" created successfully.', 'success')
        return redirect(url_for('manage_teams'))

    return render_template('teams/form.html', form_data=get_team_form_data(), team=None)

@app.route('/teams/edit/<int:team_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_TEAMS')
def edit_team(team_id):
    # Eagerly load the members to have them available for the form
    team = Team.query.options(joinedload(Team.members)).get_or_404(team_id)
    
    # Security check
    if team.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Team Name is a required field.', 'danger')
            # Re-render form with errors
            return render_template('teams/form.html', form_data=get_team_form_data(), team=team)

        # Check for duplicate name, excluding the current team itself
        existing_team = Team.query.filter(
            Team.company_id == current_user.company_id,
            Team.name == name,
            Team.id != team_id
        ).first()
        if existing_team:
            flash(f'Another team with the name "{name}" already exists.', 'warning')
            return render_template('teams/form.html', form_data=get_team_form_data(), team=team)

        # Update basic details
        team.name = name
        team.description = request.form.get('description')
        
        # --- Sync Members ---
        # Get the list of user IDs submitted from the form's checkboxes
        submitted_member_ids = request.form.getlist('member_ids')
        
        # Find the full User objects for the submitted IDs
        # We add a company_id check here as a security measure
        selected_members = User.query.filter(
            User.company_id == current_user.company_id,
            User.id.in_(submitted_member_ids)
        ).all()
        
        # SQLAlchemy is smart: assigning a new list to the relationship
        # will automatically handle adding new members and removing old ones.
        team.members = selected_members
        
        db.session.commit()
        flash(f'Team "{team.name}" updated successfully.', 'success')
        return redirect(url_for('manage_teams'))

    # For a GET request, render the form pre-filled with the team's data
    return render_template('teams/form.html', form_data=get_team_form_data(), team=team)

@app.route('/teams/view/<int:team_id>')
@login_required
@permission_required('CAN_MANAGE_TEAMS')
def view_team(team_id):
    # Eagerly load the members for display
    team = Team.query.options(joinedload(Team.members)).get_or_404(team_id)
    
    # Security check
    if team.company_id != current_user.company_id:
        abort(403)
        
    return render_template('teams/view.html', team=team)

@app.route('/teams/delete/<int:team_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_TEAMS')
def delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Security check
    if team.company_id != current_user.company_id:
        abort(403)
        
    # Future-proofing: Check if the team is assigned to any open work orders before deleting
    # if team.work_orders:
    #     flash(f'Cannot delete team "{team.name}" as it is assigned to active work orders.', 'danger')
    #     return redirect(url_for('manage_teams'))
        
    try:
        # SQLAlchemy will automatically handle deleting entries from the
        # `team_members` association table because of the relationship setup.
        db.session.delete(team)
        db.session.commit()
        flash(f'Team "{team.name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the team: {e}', 'danger')

    return redirect(url_for('manage_teams'))

# --- WORK ORDER ROUTES ---

def get_work_order_form_data():
    """Helper to fetch data for the work order form dropdowns."""
    company_id = current_user.company_id
    # Fetch all non-admin users to be potential technicians
    technicians = User.query.join(Role).filter(
        User.company_id == company_id,
        Role.is_admin == False,
        User.is_active == True
    ).order_by(User.first_name).all()

    return {
        'equipment': Equipment.query.filter_by(company_id=company_id).order_by(Equipment.name).all(),
        'locations': Location.query.filter_by(company_id=company_id, is_active=True).order_by(Location.name).all(),
        'technicians': technicians,
        'teams': Team.query.filter_by(company_id=company_id, is_active=True).order_by(Team.name).all(),
    }

@app.route('/work-orders')
@login_required
@permission_required('CAN_CREATE_WORK_ORDER') # Base permission to see the page
def manage_work_orders():
    search_query = request.args.get('q', '').strip()
    
    # --- Determine user's permissions ---
    can_manage_all = current_user.role.is_admin or 'CAN_MANAGE_ALL_WORK_ORDERS' in [p.name for p in current_user.role.permissions]
    can_approve = current_user.role.is_admin or 'CAN_APPROVE_WORK_ORDER' in [p.name for p in current_user.role.permissions]

    # --- Base Query ---
    # Eagerly load all related data needed for the table display to prevent N+1 queries.
    base_query = WorkOrder.query.options(
        joinedload(WorkOrder.equipment),
        joinedload(WorkOrder.location),
        joinedload(WorkOrder.assigned_user),
        joinedload(WorkOrder.assigned_team),
        joinedload(WorkOrder.created_by) # Needed for the requests tab
    ).filter(WorkOrder.company_id == current_user.company_id)

    # --- Filter query based on user role ---
    work_orders_query = base_query
    if not can_manage_all:
        # A non-manager can see WOs they created, are assigned to, or are on a team they are a member of.
        user_team_ids = [team.id for team in current_user.teams]
        work_orders_query = work_orders_query.filter(
            db.or_(
                WorkOrder.created_by_id == current_user.id,
                WorkOrder.assigned_to_user_id == current_user.id,
                WorkOrder.assigned_to_team_id.in_(user_team_ids)
            )
        )

    # --- Handle Search Logic (Corrected) ---
    if search_query:
        search_term = f"%{search_query}%"
        
        # Build a list of potential filter conditions for text-based fields
        filters = [
            WorkOrder.title.ilike(search_term),
            Equipment.name.ilike(search_term),
            Equipment.equipment_id.ilike(search_term)
        ]
        
        # Only try to match the Work Order ID if the search query is a number
        if search_query.isdigit():
            filters.append(WorkOrder.id == int(search_query))
            
        # Apply the filters, joined by OR
        work_orders_query = work_orders_query.join(WorkOrder.equipment).filter(db.or_(*filters))
    
    # --- Fetch "Requests" (On Hold work orders) if user has approval permission ---
    requests_list = []
    if can_approve:
        # We query separately for requests to keep the logic clean
        requests_list = WorkOrder.query.options(
            joinedload(WorkOrder.equipment),
            joinedload(WorkOrder.created_by)
        ).filter(
            WorkOrder.company_id == current_user.company_id,
            WorkOrder.status == 'On Hold'
        ).order_by(WorkOrder.created_at.desc()).all()

    # --- Get the final list of "active" work orders for the main table ---
    work_orders = work_orders_query.filter(
        ~WorkOrder.status.in_(['On Hold', 'Rejected'])
    ).order_by(WorkOrder.created_at.desc()).all()

    return render_template(
        'work_orders/index.html',
        work_orders=work_orders,
        work_order_requests=requests_list,
        can_approve=can_approve,
        search_query=search_query
    )
    
@app.route('/work-orders/view/<int:wo_id>')
@login_required
@permission_required('CAN_CREATE_WORK_ORDER') # A base permission to access any WO page
def view_work_order(wo_id):
    # Eagerly load all relationships needed for the view page in one go
    # This is highly efficient and prevents multiple database queries.
    work_order = WorkOrder.query.options(
        joinedload(WorkOrder.equipment).joinedload(Equipment.location),
        joinedload(WorkOrder.equipment).joinedload(Equipment.category),
        joinedload(WorkOrder.location),
        joinedload(WorkOrder.created_by).joinedload(User.role),
        joinedload(WorkOrder.assigned_user),
        joinedload(WorkOrder.assigned_team)
    ).get_or_404(wo_id)

    # --- Security & Permission Checks ---
    # 1. Ensure the Work Order belongs to the user's company
    if work_order.company_id != current_user.company_id:
        abort(403)

    # 2. Determine if the current user has permission to view this specific WO
    can_manage_all = current_user.role.is_admin or 'CAN_MANAGE_ALL_WORK_ORDERS' in [p.name for p in current_user.role.permissions]
    user_team_ids = [team.id for team in current_user.teams]

    # A user can view this WO if:
    # - They have permission to manage ALL work orders, OR
    # - They are the one who created it, OR
    # - It is directly assigned to them, OR
    # - It is assigned to a team they are a member of.
    can_view = (
        can_manage_all or
        work_order.created_by_id == current_user.id or
        work_order.assigned_to_user_id == current_user.id or
        (work_order.assigned_to_team_id and work_order.assigned_to_team_id in user_team_ids)
    )
    
    if not can_view:
        # If none of the conditions are met, the user is forbidden from seeing this page.
        abort(403)

    return render_template('work_orders/view.html', wo=work_order)
    
@app.route('/work-orders/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_CREATE_WORK_ORDER')
def add_work_order():
    if request.method == 'POST':
        # --- 1. Validation ---
        if not all([request.form.get('title'), request.form.get('equipment_id'), request.form.get('work_order_type')]):
            flash('Title, Equipment, and Type are required fields.', 'danger')
            return render_template('work_orders/form.html', form_data=get_work_order_form_data(), wo=None)

        # --- 2. Determine Approval Status based on User Role ---
        can_auto_approve = current_user.role.is_admin or 'CAN_APPROVE_WORK_ORDER' in [p.name for p in current_user.role.permissions]
        status = 'Open' if can_auto_approve else 'On Hold'
        is_approved = can_auto_approve

        # --- 3. Create Work Order Object ---
        new_wo = WorkOrder(
            company_id=current_user.company_id,
            title=request.form.get('title'),
            priority=request.form.get('priority'),
            equipment_id=request.form.get('equipment_id'),
            location_id=request.form.get('location_id') or None,
            work_order_type=request.form.get('work_order_type'),
            description=request.form.get('description'),
            assigned_to_user_id=request.form.get('assigned_to_user_id') or None,
            assigned_to_team_id=request.form.get('assigned_to_team_id') or None,
            scheduled_date=request.form.get('scheduled_date') or None,
            due_date=request.form.get('due_date') or None,
            estimated_duration=request.form.get('estimated_duration') or None,
            created_by_id=current_user.id,
            status=status,
            is_approved=is_approved
        )
        
        db.session.add(new_wo)
        save_actions = []

        try:
            db.session.flush() # Get the new_wo.id for file naming
            # --- 4. Handle Media Uploads (using our generic helper) ---
            saved_files, save_actions = process_uploads(new_wo, request.files, 'work_orders')
            new_wo.images = saved_files['images'] or []
            new_wo.videos = saved_files['videos'] or []
            new_wo.audio_files = saved_files['audio_files'] or []
            new_wo.documents = saved_files['documents'] or []
            
            # --- 5. Commit and Save ---
            db.session.commit()
            for file, path in save_actions:
                file.save(path)

            if can_auto_approve:
                # If auto-approved and assigned, send notification email
                if new_wo.assigned_to_user_id or new_wo.assigned_to_team_id:
                    send_work_order_assignment_email(new_wo)
                flash(f'Work Order #{new_wo.id} created successfully.', 'success')
            else:
                flash(f'Work Order request #{new_wo.id} submitted for approval.', 'info')
                send_approval_request_email(new_wo)

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            
        return redirect(url_for('manage_work_orders'))
    
    # Get the pre-selected equipment ID from the URL query string, if it exists
    preselected_equipment_id = request.args.get('equipment_id', type=int)

    return render_template(
        'work_orders/form.html', 
        form_data=get_work_order_form_data(), 
        wo=None,
        preselected_equipment_id=preselected_equipment_id
    )

@app.route('/work-orders/edit/<int:wo_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_EDIT_WORK_ORDER') # Base permission to access the page
def edit_work_order(wo_id):
    # Eagerly load relationships to pre-fill the form efficiently
    work_order = WorkOrder.query.options(
        joinedload(WorkOrder.equipment),
        joinedload(WorkOrder.location),
        joinedload(WorkOrder.created_by),
        joinedload(WorkOrder.assigned_user),
        joinedload(WorkOrder.assigned_team)
    ).get_or_404(wo_id)
    
    # --- Security & Permission Checks ---
    if work_order.company_id != current_user.company_id:
        abort(403)
    
    can_manage = current_user.role.is_admin or 'CAN_APPROVE_WORK_ORDER' in [p.name for p in current_user.role.permissions]
    is_creator = work_order.created_by_id == current_user.id

    # A user can only edit if they are a manager/admin OR they are the original creator
    if not can_manage and not is_creator:
        flash('You do not have permission to edit this work order.', 'danger')
        return redirect(url_for('manage_work_orders'))

    if request.method == 'POST':
        save_actions = []
        try:
            # --- Store the OLD assignee IDs before making any changes ---
            old_user_id = work_order.assigned_to_user_id
            old_team_id = work_order.assigned_to_team_id

            # --- 1. Update Standard Fields ---
            work_order.title = request.form.get('title')
            work_order.priority = request.form.get('priority')
            work_order.equipment_id = request.form.get('equipment_id')
            work_order.location_id = request.form.get('location_id') or None
            work_order.work_order_type = request.form.get('work_order_type')
            work_order.description = request.form.get('description')
            work_order.assigned_to_user_id = request.form.get('assigned_to_user_id') or None
            work_order.assigned_to_team_id = request.form.get('assigned_to_team_id') or None
            scheduled_str = request.form.get('scheduled_date')
            work_order.scheduled_date = datetime.strptime(scheduled_str, '%Y-%m-%d').date() if scheduled_str else None
            due_str = request.form.get('due_date')
            work_order.due_date = datetime.strptime(due_str, '%Y-%m-%d').date() if due_str else None
            work_order.estimated_duration = request.form.get('estimated_duration') or None
            
            # --- 2. RE-APPROVAL LOGIC ---
            if not can_manage:
                work_order.status = 'On Hold'
                work_order.is_approved = False
                flash('Your changes have been submitted for re-approval.', 'info')
                send_approval_request_email(work_order)
            
            # --- 3. Handle New Media Uploads ---
            saved_files, save_actions = process_uploads(work_order, request.files, 'work_orders')
            if saved_files['images']: work_order.images = (work_order.images or []) + saved_files['images']
            if saved_files['videos']: work_order.videos = (work_order.videos or []) + saved_files['videos']
            if saved_files['audio_files']: work_order.audio_files = (work_order.audio_files or []) + saved_files['audio_files']
            if saved_files['documents']: work_order.documents = (work_order.documents or []) + saved_files['documents']
            
            flag_modified(work_order, "images"); flag_modified(work_order, "videos");
            flag_modified(work_order, "audio_files"); flag_modified(work_order, "documents");

            # --- 4. Re-assignment Notification Logic ---
            new_user_id = int(work_order.assigned_to_user_id) if work_order.assigned_to_user_id else None
            new_team_id = int(work_order.assigned_to_team_id) if work_order.assigned_to_team_id else None
            assignment_changed = (old_user_id != new_user_id) or (old_team_id != new_team_id)
            
            # Only send if the assignment changed AND the WO is in an active (not On Hold) state.
            if assignment_changed and work_order.status in ['Open', 'In Progress']:
                send_work_order_assignment_email(work_order)

            # --- 5. Commit to DB, then Save Files ---
            db.session.commit()
            for file, path in save_actions:
                file.save(path)
                
            flash(f'Work Order #{work_order.id} updated successfully.', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the work order: {e}', 'danger')
            print(f"Error in edit_work_order: {e}")
            
        return redirect(url_for('manage_work_orders'))

    # For a GET request
    return render_template('work_orders/form.html', form_data=get_work_order_form_data(), wo=work_order)

@app.route('/work-orders/approve/<int:wo_id>', methods=['POST'])
@login_required
@permission_required('CAN_APPROVE_WORK_ORDER')
def approve_work_order(wo_id):
    work_order = WorkOrder.query.get_or_404(wo_id)
    if work_order.company_id != current_user.company_id or work_order.status != 'On Hold':
        abort(403) # Prevent approving already approved/completed WOs

    # --- Update Status ---
    work_order.status = 'Open'
    work_order.is_approved = True
    db.session.commit()

    # --- Send Notifications ---
    send_wo_status_change_email(work_order, is_approved=True)
    # If it was assigned during creation, notify the technician/team now
    if work_order.assigned_to_user_id or work_order.assigned_to_team_id:
        send_work_order_assignment_email(work_order)

    flash(f'Work Order #{work_order.id} has been approved and is now Open.', 'success')
    return redirect(url_for('manage_work_orders'))


@app.route('/work-orders/reject/<int:wo_id>', methods=['POST'])
@login_required
@permission_required('CAN_APPROVE_WORK_ORDER')
def reject_work_order(wo_id):
    # Eagerly load the created_by relationship so we can access it after deletion
    work_order = WorkOrder.query.options(joinedload(WorkOrder.created_by)).get_or_404(wo_id)

    # Security checks
    if work_order.company_id != current_user.company_id or work_order.status != 'On Hold':
        abort(403)

    rejection_reason = request.form.get('rejection_reason')
    if not rejection_reason:
        flash('A reason is required to reject and delete a work order request.', 'danger')
        return redirect(url_for('manage_work_orders'))

    try:
        # --- Step 1: Prepare Notification Data BEFORE Deleting ---
        # The work_order object will be expired after the commit, so we
        # store its details in a temporary object for the email function.
        class TempWOInfo:
            def __init__(self, wo, reason):
                self.id = wo.id
                self.title = wo.title
                self.created_by = wo.created_by
                self.rejection_reason = reason
                self.guest_reporter_name = wo.guest_reporter_name
                self.guest_reporter_email = wo.guest_reporter_email
        
        notification_data = TempWOInfo(work_order, rejection_reason)

        # --- Step 2: Delete Files and Database Record ---
        delete_all_uploads(work_order, 'work_orders')
        db.session.delete(work_order)
        db.session.commit()

        # --- Step 3: Send Notification AFTER Successful Deletion ---
        send_wo_status_change_email(notification_data, is_approved=False)

        flash(f'Work Order request #{notification_data.id} has been rejected and deleted.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while rejecting the work order: {e}', 'danger')
        print(f"Error in reject_work_order: {e}") # For debugging

    return redirect(url_for('manage_work_orders'))

    
@app.route('/work-orders/update-status/<int:wo_id>', methods=['POST'])
@login_required
# We'll use a more general permission here, but you could create a specific one
@permission_required('CAN_EDIT_WORK_ORDER') 
def update_work_order_status(wo_id):
    work_order = WorkOrder.query.get_or_404(wo_id)
    if work_order.company_id != current_user.company_id:
        abort(403)
        
    new_status = request.json.get('status')
    valid_statuses = ['Open', 'In Progress', 'On Hold', 'Completed']
    
    if not new_status or new_status not in valid_statuses:
        return jsonify({'error': 'Invalid status provided.'}), 400

    try:
        work_order.status = new_status
        # If marking as completed, set the completion timestamp
        if new_status == 'Completed':
            work_order.completed_at = datetime.now(timezone.utc)
        else:
            work_order.completed_at = None # Clear timestamp if reopening

        db.session.commit()
        
        # You could add email notification logic here if needed
        
        return jsonify({
            'success': True, 
            'new_status': new_status,
            'message': f'Work Order status updated to "{new_status}".'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {e}'}), 500
    
@app.route('/work-orders/delete/<int:wo_id>', methods=['POST'])
@login_required
def delete_work_order(wo_id):
    work_order = WorkOrder.query.get_or_404(wo_id)
    
    # --- Security & Permission Checks ---
    
    # 1. Ensure the work order belongs to the user's company
    if work_order.company_id != current_user.company_id:
        abort(403)

    # 2. Check if the user has permission to delete this specific work order
    can_manage = current_user.role and (current_user.role.is_admin or 'CAN_APPROVE_WORK_ORDER' in [p.name for p in current_user.role.permissions])
    is_creator = work_order.created_by_id == current_user.id

    if not can_manage and not is_creator:
        # If the user is neither a manager/admin nor the creator, forbid access.
        abort(403)

    # Note: As per your earlier rule, if a non-manager deletes, it should require re-approval.
    # For a destructive action like deletion, we will treat it as final. If you want a
    # "request deletion" workflow, that would require a different status and route.
    
    try:
        wo_id_for_flash = work_order.id # Store ID for the flash message
        
        # Step 1: Delete associated media files using the generic helper
        delete_all_uploads(work_order, 'work_orders')
        
        # Step 2: Delete the database record
        # SQLAlchemy will handle removing associations from other tables (like team_members) automatically if configured.
        db.session.delete(work_order)
        db.session.commit()
        
        flash(f'Work Order #{wo_id_for_flash} and all associated media have been deleted.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the work order: {e}', 'danger')
        print(f"Error in delete_work_order: {e}")

    return redirect(url_for('manage_work_orders'))

@app.route('/work-orders/<int:wo_id>/delete-media', methods=['POST'])
@login_required
@permission_required('CAN_EDIT_WORK_ORDER') # User needs permission to edit to delete media
def delete_work_order_media(wo_id):
    work_order = WorkOrder.query.get_or_404(wo_id)
    if work_order.company_id != current_user.company_id:
        abort(403)
        
    filename = request.form.get('filename')
    file_type_key = request.form.get('file_type') # e.g., 'images', 'audio_files'
    
    if not all([filename, file_type_key]):
        flash('Missing file information for deletion.', 'danger')
        return redirect(url_for('edit_work_order', wo_id=wo_id))

    # Map the model attribute name to the physical folder name
    folder_map = {'images': 'images', 'videos': 'videos', 'audio_files': 'audio', 'documents': 'documents'}
    folder_name = folder_map.get(file_type_key)

    if not folder_name:
        flash('Invalid file type specified.', 'danger')
        return redirect(url_for('edit_work_order', wo_id=wo_id))

    current_files = getattr(work_order, file_type_key, [])
    
    if filename in current_files:
        try:
            # --- Step 1: Delete the physical file ---
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'work_orders', folder_name, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                
            # --- Step 2: Remove the filename from the database list ---
            current_files.remove(filename)
            setattr(work_order, file_type_key, current_files or None)
            
            flag_modified(work_order, file_type_key)
            db.session.commit()
            
            flash(f'File "{filename.split("_")[-1]}" deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while deleting the file: {e}", 'danger')
    else:
        flash('File not found for this work order.', 'warning')
        
    return redirect(url_for('edit_work_order', wo_id=wo_id))

# --- METER MANAGEMENT ROUTES ---

def get_meter_form_data():
    """Helper to fetch data for the meter form dropdowns."""
    company_id = current_user.company_id
    return {
        'equipment': Equipment.query.filter_by(company_id=company_id).order_by(Equipment.name).all(),
        'locations': Location.query.filter_by(company_id=company_id, is_active=True).order_by(Location.name).all(),
    }

@app.route('/meters')
@login_required
@permission_required('CAN_MANAGE_METERS')
def manage_meters():
    search_query = request.args.get('q', '').strip()
    
    # Base query for meters in the current company
    query = Meter.query.filter(Meter.company_id == current_user.company_id)
    
    # Eagerly load related equipment and location for the table display
    query = query.options(
        joinedload(Meter.equipment),
        joinedload(Meter.location)
    )

    if search_query:
        search_term = f"%{search_query}%"
        # Search by meter name, topic, or associated equipment name
        query = query.filter(
            db.or_(
                Meter.name.ilike(search_term),
                Meter.mqtt_topic.ilike(search_term),
                Equipment.name.ilike(search_term)
            )
        )

    meters_list = query.order_by(Meter.name).all()
    
    return render_template(
        'meters/index.html',
        meters_list=meters_list,
        search_query=search_query
    )
    
@app.route('/meters/view/<int:meter_id>')
@login_required
@permission_required('CAN_VIEW_METERS')
def view_meter(meter_id):
    # Eagerly load related models to prevent extra database queries in the template.
    # This fetches the meter, its equipment, and its location all in one go.
    meter = Meter.query.options(
        joinedload(Meter.equipment),
        joinedload(Meter.location)
    ).get_or_404(meter_id)

    # --- Security Check ---
    # Ensure the meter being viewed belongs to the currently logged-in user's company.
    if meter.company_id != current_user.company_id:
        abort(403) # Forbidden

    return render_template('meters/view.html', meter=meter)

@app.route('/meters/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_ADD_METERS')
def add_meter():
    if request.method == 'POST':
        # --- 1. Form Validation ---
        name = request.form.get('name', '').strip()
        topic = request.form.get('mqtt_topic', '').strip()
        equipment_id = request.form.get('equipment_id')

        if not all([name, topic, equipment_id]):
            flash('Meter Name, MQTT Topic, and Equipment are required fields.', 'danger')
            return render_template('meters/form.html', form_data=get_meter_form_data(), meter=None)

        # Check for unique MQTT topic across the entire system (topics are global)
        if Meter.query.filter_by(mqtt_topic=topic).first():
            flash(f'The MQTT Topic "{topic}" is already registered to another meter.', 'warning')
            return render_template('meters/form.html', form_data=get_meter_form_data(), meter=None)

        # --- 2. Create Meter Object ---
        new_meter = Meter(
            company_id=current_user.company_id,
            name=name,
            mqtt_topic=topic,
            equipment_id=equipment_id,
            location_id=request.form.get('location_id') or None,
            is_active=True # Default new meters to active
        )
        
        db.session.add(new_meter)
        save_actions = []

        try:
            # --- Transactional Block ---
            db.session.flush() # Flush to get the new_meter.id for file naming
            
            # Use our generic helper, passing 'meters' as the subdirectory name
            saved_files, save_actions = process_uploads(new_meter, request.files, 'meters')
            
            new_meter.images = saved_files['images'] or []
            new_meter.videos = saved_files['videos'] or []
            new_meter.audio_files = saved_files['audio_files'] or []
            new_meter.documents = saved_files['documents'] or []
            
            # --- 3. Commit to DB, then Save Files ---
            db.session.commit()
            for file, path in save_actions:
                file.save(path)
            
            flash(f'Meter "{name}" has been registered successfully.', 'success')
            return redirect(url_for('manage_meters'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while registering the meter: {e}', 'danger')
            print(f"Error in add_meter: {e}") # For debugging

    # For a GET request
    return render_template('meters/form.html', form_data=get_meter_form_data(), meter=None)

@app.route('/meters/edit/<int:meter_id>', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_EDIT_METERS')
def edit_meter(meter_id):
    meter = Meter.query.get_or_404(meter_id)
    if meter.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        save_actions = []
        try:
            meter.name = request.form.get('name')
            meter.mqtt_topic = request.form.get('mqtt_topic')
            meter.equipment_id = request.form.get('equipment_id')
            meter.location_id = request.form.get('location_id') or None
            
            # Handle new file uploads and append to existing
            saved_files, save_actions = process_uploads(meter, request.files, 'meters')
            if saved_files['images']: meter.images = (meter.images or []) + saved_files['images']
            if saved_files['videos']: meter.videos = (meter.videos or []) + saved_files['videos']
            if saved_files['audio_files']: meter.audio_files = (meter.audio_files or []) + saved_files['audio_files']
            if saved_files['documents']: meter.documents = (meter.documents or []) + saved_files['documents']
            
            flag_modified(meter, "images"); flag_modified(meter, "videos");
            flag_modified(meter, "audio_files"); flag_modified(meter, "documents");

            db.session.commit()
            for file, path in save_actions:
                file.save(path)
                
            flash(f'Meter "{meter.name}" updated successfully.', 'success')
            return redirect(url_for('manage_meters'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

    return render_template('meters/form.html', form_data=get_meter_form_data(), meter=meter)

@app.route('/meters/delete/<int:meter_id>', methods=['POST'])
@login_required
@permission_required('CAN_DELETE_METERS')
def delete_meter(meter_id):
    meter = Meter.query.get_or_404(meter_id)
    if meter.company_id != current_user.company_id:
        abort(403)
    
    try:
        delete_all_uploads(meter, 'meters')
        db.session.delete(meter)
        db.session.commit()
        flash(f'Meter "{meter.name}" has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')
        
    return redirect(url_for('manage_meters'))

@app.route('/meters/<int:meter_id>/delete-media', methods=['POST'])
@login_required
@permission_required('CAN_EDIT_METERS')
def delete_meter_media(meter_id):
    meter = Meter.query.get_or_404(meter_id)
    if meter.company_id != current_user.company_id:
        abort(403)
    
    # This logic is now generic and safe
    filename = request.form.get('filename')
    file_type_key = request.form.get('file_type')
    folder_map = {'images': 'images', 'videos': 'videos', 'audio_files': 'audio', 'documents': 'documents'}
    folder_name = folder_map.get(file_type_key)

    if not all([filename, file_type_key, folder_name]):
        flash('Invalid request for file deletion.', 'danger')
        return redirect(url_for('edit_meter', meter_id=meter_id))
    
    current_files = getattr(meter, file_type_key, [])
    if filename in current_files:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'meters', folder_name, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            
            current_files.remove(filename)
            setattr(meter, file_type_key, current_files or [])
            flag_modified(meter, file_type_key)
            db.session.commit()
            flash('File deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting file: {e}', 'danger')
    else:
        flash('File not found.', 'warning')
        
    return redirect(url_for('edit_meter', meter_id=meter_id))

# --- ANALYTICS ROUTES ---

@app.route('/analytics/meters')
@login_required
@permission_required('CAN_VIEW_REPORTS') # Reuse the reports permission
def view_meter_analytics():
    # Get all meters for the current company to populate the dropdown
    meters = Meter.query.filter_by(company_id=current_user.company_id, is_active=True).order_by(Meter.name).all()
    
    return render_template('analytics/meters.html', meters=meters)

# --- USER PROFILE ROUTE ---

def get_profile_form_data():
    """Helper to fetch data for the profile edit form's dropdowns."""
    company_id = current_user.company_id
    return {
        'departments': Department.query.filter_by(company_id=company_id, is_active=True).order_by(Department.name).all(),
        'roles': Role.query.filter_by(company_id=company_id).order_by(Role.name).all()
    }

@app.route('/profile')
@login_required
def view_profile():
    user = User.query.options(
        joinedload(User.role),
        joinedload(User.department)
    ).get(current_user.id)
    
    return render_template('profile/view.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get_or_404(current_user.id)
    is_admin = current_user.role and current_user.role.is_admin

    if request.method == 'POST':
        # --- Fields anyone can change ---
        user.username = request.form.get('username')
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.phone = request.form.get('phone')

        # --- Admin-only fields ---
        if is_admin:
            user.department_id = request.form.get('department_id') or None
            user.role_id = request.form.get('role_id') or None
            # Handle is_active checkbox (value is only sent if checked)
            user.is_active = 'is_active' in request.form
        
        # --- Uniqueness validation ---
        # Check if new username is unique (and not the user's current username)
        existing_user = User.query.filter(User.username == user.username, User.id != user.id).first()
        if existing_user:
            flash('That username is already taken. Please choose another.', 'warning')
            # We need to re-fetch form data if validation fails
            form_data = get_profile_form_data()
            return render_template('profile/edit.html', user=user, is_admin=is_admin, form_data=form_data)

        db.session.commit()
        flash('Your profile has been updated successfully.', 'success')
        return redirect(url_for('view_profile'))

    # For a GET request, get the data needed for dropdowns
    form_data = get_profile_form_data() if is_admin else None
    return render_template('profile/edit.html', user=user, is_admin=is_admin, form_data=form_data)

@app.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # --- 1. Validate inputs ---
        if not all([current_password, new_password, confirm_new_password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('change_password'))

        # --- 2. Check if the current password is correct ---
        if not current_user.check_password(current_password):
            flash('Your current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        # --- 3. Check if the new password and confirmation match ---
        if new_password != confirm_new_password:
            flash('New password and confirmation do not match.', 'danger')
            return redirect(url_for('change_password'))
        
        # --- 4. Update the password ---
        current_user.set_password(new_password)
        current_user.password_reset_required = False
        db.session.commit()
        
        flash('Your password has been updated successfully.', 'success')
        return redirect(url_for('view_profile'))

    return render_template('profile/change_password.html')

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    is_admin = current_user.role and current_user.role.is_admin
    is_self = current_user.id == user_to_delete.id

    # --- PERMISSION CHECKS ---
    
    # 1. A non-admin cannot delete another user.
    if not is_admin and not is_self:
        abort(403) # Forbidden

    # 2. A user (even an admin) can only delete users within their own company.
    if user_to_delete.company_id != current_user.company_id:
        abort(403)

    # 3. Prevent the last admin in a company from deleting themselves.
    if is_self and is_admin:
        admin_count = User.query.join(Role).filter(
            User.company_id == current_user.company_id,
            Role.is_admin == True
        ).count()
        if admin_count <= 1:
            flash('You cannot delete the last administrator account for this company.', 'danger')
            return redirect(url_for('view_profile'))

    # If all checks pass, proceed with deletion
    try:
        # Future-proofing: Reassign or nullify work orders, etc., before deleting
        # For example: WorkOrder.query.filter_by(assigned_technician_id=user_to_delete.id).update({'assigned_technician_id': None})

        db.session.delete(user_to_delete)
        db.session.commit()
        
        if is_self:
            # If the user deleted themselves, log them out
            logout_user()
            flash('Your account has been successfully deleted.', 'success')
            return redirect(url_for('login'))
        else:
            # If an admin deleted another user
            flash(f'User "{user_to_delete.username}" has been successfully deleted.', 'success')
            # --- THIS IS THE FIX ---
            return redirect(url_for('manage_users'))

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the account: {e}', 'danger')
        if is_self:
            return redirect(url_for('view_profile'))
        else:
            # Redirect to user management page in the future
            return redirect(url_for('manage_users'))
        
# --- NOTIFICATION ROUTES ---

@app.route('/notifications')
@login_required
def notification_logs():
    # --- THIS IS THE FIX ---
    # Filter the logs to get ONLY those belonging to the currently logged-in user.
    logs = NotificationLog.query.filter_by(
    user_id=current_user.id
    ).order_by(NotificationLog.created_at.desc()).paginate(per_page=20)
    
    # You can also add logic here to mark these notifications as "read"
    # For example:
    # NotificationLog.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    # db.session.commit()

    return render_template('notifications/index.html', logs=logs)

# --- SOCKETIO EVENT HANDLERS ---

@socketio.on('connect')
def handle_connect():
    """
    Event handler for when a new client connects via WebSocket.
    """
    print('Client connected to WebSocket')

@socketio.on('disconnect')
def handle_disconnect():
    """Event handler for when a client disconnects."""
    print('Client disconnected from WebSocket')

@socketio.on('subscribe')
def handle_subscribe(data):
    """
    Handler for when a browser client wants to subscribe to a topic.
    The client joins a 'room' named after the topic.
    """
    topic = data.get('topic')
    if topic:
        # Leave any previous room to only get messages for one topic at a time
        previous_topic = session.get('mqtt_topic')
        if previous_topic and previous_topic != topic:
            leave_room(previous_topic)
            print(f"Client left room: {previous_topic}")
        
        # Join the new room
        join_room(topic)
        session['mqtt_topic'] = topic
        print(f'Client {request.sid} joined room: {topic}')

@socketio.on('unsubscribe')
def handle_unsubscribe():
    """Handler for when a browser client unsubscribes."""
    topic = session.pop('mqtt_topic', None)
    if topic:
        leave_room(topic)
        print(f'Client {request.sid} left room: {topic}')

# --- THIS IS THE NEW HANDLER ---
@socketio.on('forward_mqtt_message')
def handle_forward_mqtt_message(data):
    """
    This is a relay handler. It receives a message from our internal
    MQTT client script and then broadcasts it to the correct room/topic
    where browser clients are listening.
    """
    topic = data.get('topic')
    payload = data.get('payload')
    
    if topic and payload:
        # This is the SERVER-SIDE emit, which DOES have the 'room' argument.
        # It sends an 'mqtt_message' event to all clients in the specified room.
        emit('mqtt_message', payload, room=topic)
        # Optional: uncomment the line below for very verbose logging
        # print(f"Broadcasted MQTT message to room: {topic}")

# --- SUPERADMIN ROUTES ---

@app.route('/super-admin')
@super_admin_required
def super_admin_dashboard():
    search_query = request.args.get('q', '').strip()
    all_companies = load_json_data(ORG_DATA_FILE)
    
    if search_query:
        filtered_companies = [
            company for company in all_companies
            if search_query.lower() in company['company_name'].lower() or \
               search_query.lower() in company['email'].lower()
        ]
    else:
        filtered_companies = all_companies

    return render_template(
        'super_admin.html', 
        companies=filtered_companies, 
        search_query=search_query,
        hide_sidebar=True
    )

@app.route('/super-admin/add', methods=['POST'])
@super_admin_required
def add_company():
    company_name = request.form.get('company_name')
    email = request.form.get('email')
    users_allowed_str = request.form.get('users_allowed')

    if not all([company_name, email, users_allowed_str]):
        flash('All fields (Company Name, Email, Users Allowed) are required.', 'danger')
        return redirect(url_for('super_admin_dashboard'))

    try:
        users_allowed = int(users_allowed_str)
        if users_allowed <= 0:
            flash('Number of users allowed must be a positive number.', 'danger')
            return redirect(url_for('super_admin_dashboard'))
    except (ValueError, TypeError):
        flash('Please enter a valid number for users allowed.', 'danger')
        return redirect(url_for('super_admin_dashboard'))

    companies = load_json_data(ORG_DATA_FILE)
    
    if any(c['email'] == email for c in companies):
        flash(f'An entry for the email {email} already exists.', 'warning')
        return redirect(url_for('super_admin_dashboard'))

    new_company = {
        "company_name": company_name,
        "email": email,
        "key": uuid.uuid4().hex,
        "users_allowed": users_allowed
    }
    companies.append(new_company)
    save_json_data(ORG_DATA_FILE, companies)
    flash(f'Successfully added {company_name} with a limit of {users_allowed} users.', 'success')
    return redirect(url_for('super_admin_dashboard'))

@app.route('/super-admin/delete', methods=['POST'])
@super_admin_required
def delete_company():
    email_to_delete = request.form.get('email')
    companies = load_json_data(ORG_DATA_FILE)
    
    updated_companies = [c for c in companies if c['email'] != email_to_delete]

    if len(updated_companies) < len(companies):
        save_json_data(ORG_DATA_FILE, updated_companies)
        flash(f'Successfully deleted entry for {email_to_delete}.', 'success')
    else:
        flash(f'Could not find an entry for {email_to_delete}.', 'danger')

    return redirect(url_for('super_admin_dashboard'))

# --- CLI CONFIGURATION ---

@app.cli.command("init-db")
def init_db():
    """Drops and recreates the database, then seeds a default company and admin user."""
    db.drop_all()
    db.create_all()
    print("Database tables created.")

    admin_email = 'admin@example.com'
    if not User.query.filter_by(email=admin_email).first():
        # 1. Create the default company
        default_company = Company(name='Default Company', user_limit=10)
        db.session.add(default_company)
        db.session.flush()  # Ensures default_company.id is available

        # 2. Create the default roles (Admin, Manager, etc.) for this company
        create_default_roles_and_permissions(default_company.id)

        # 3. Find the newly created Admin role for this specific company
        admin_role = Role.query.filter_by(company_id=default_company.id, name='Admin').first()

        # 4. Add a check to ensure the Admin role was found
        if not admin_role:
            print("CRITICAL ERROR: Default Admin role could not be found after creation.")
            return

        # 5. Create the admin user and assign the Admin role's ID
        admin_user = User(
            company_id=default_company.id,
            role_id=admin_role.id,  # Explicitly assigning the Admin role
            username='admin',
            email=admin_email,
            first_name='Default',
            last_name='Admin'
        )
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        db.session.commit()
        print(f"Default app admin user ({admin_email}) created with password 'admin123'.")
    else:
        print("Default app admin user already exists.")

@app.cli.command("delete-db")
def delete_db():
    db.drop_all()
    print("Database tables deleted.")
    
@app.cli.command("cleanup-logs")
def cleanup_logs():
    """
    Finds and deletes notification logs that are older than their
    retention period. To be run by a scheduler (e.g., cron) once a day.
    """
    with app.app_context():
        # --- Password credential logs (1 day retention) ---
        one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
        old_password_logs = NotificationLog.query.filter(
            NotificationLog.category == 'credentials',
            NotificationLog.created_at < one_day_ago
        ).all()
        
        if old_password_logs:
            print(f"Deleting {len(old_password_logs)} old credential notification(s)...")
            for log in old_password_logs:
                db.session.delete(log)

        # You can add other cleanup logic here in the future
        # e.g., deleting general notifications older than 30 days

        db.session.commit()
        print("Log cleanup complete.")

if __name__ == '__main__':
    socketio.run(app, debug=True, port=8080, allow_unsafe_werkzeug=True)