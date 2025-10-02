import os
import json
import uuid
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, session, abort, jsonify
from flask_session import Session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, bcrypt, User, Company, Role, Location, Permission, Category, Department, Equipment, Unit, Currency, InventoryItem, Vendor, VendorContact
from sqlalchemy import func, cast, text, case
import pycountry
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.orm import joinedload, aliased
from werkzeug.utils import secure_filename
import pint
from sqlalchemy.dialects.postgresql import JSONB

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

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
    permission_names = [
        'CAN_MANAGE_ROLES', 'CAN_MANAGE_USERS', 'CAN_VIEW_DASHBOARD',
        'CAN_CREATE_WORK_ORDER', 'CAN_EDIT_WORK_ORDER', 'CAN_DELETE_WORK_ORDER',
        'CAN_MANAGE_ASSETS', 'CAN_VIEW_REPORTS', 'CAN_MANAGE_CATEGORIES', 'CAN_MANAGE_DEPARTMENTS',
        'CAN_MANAGE_LOCATIONS', 'CAN_MANAGE_EQUIPMENT', 'CAN_MANAGE_UNITS', 'CAN_MANAGE_CURRENCIES',
        'CAN_MANAGE_INVENTORY', 'CAN_MANAGE_VENDORS'
    ]
    all_permissions = []
    for name in permission_names:
        perm = Permission.query.filter_by(name=name).first()
        if not perm:
            perm = Permission(name=name)
            db.session.add(perm)
        all_permissions.append(perm)
    db.session.commit()

    roles_config = {
        'Admin': {'desc': 'Full access to all system features.', 'is_admin': True, 'perms': permission_names},
        'Manager': {'desc': 'Can manage work orders, assets, and users.', 'is_admin': False, 'perms': ['CAN_VIEW_DASHBOARD', 'CAN_CREATE_WORK_ORDER', 'CAN_EDIT_WORK_ORDER', 'CAN_MANAGE_ASSETS', 'CAN_MANAGE_USERS', 'CAN_MANAGE_CATEGORIES', 'CAN_MANAGE_DEPARTMENTS', 'CAN_MANAGE_LOCATIONS', 'CAN_MANAGE_EQUIPMENT', 'CAN_MANAGE_UNITS', 'CAN_MANAGE_CURRENCIES', 'CAN_MANAGE_INVENTORY', 'CAN_MANAGE_VENDORS']},
        'Technician': {'desc': 'Can view and update assigned work orders.', 'is_admin': False, 'perms': ['CAN_VIEW_DASHBOARD', 'CAN_EDIT_WORK_ORDER']},
        'Viewer': {'desc': 'Read-only access to dashboards and reports.', 'is_admin': False, 'perms': ['CAN_VIEW_DASHBOARD', 'CAN_VIEW_REPORTS']}
    }

    for name, config in roles_config.items():
        role = Role(
            company_id=company_id,
            name=name,
            description=config['desc'],
            is_admin=config['is_admin']
        )
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
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    signup_data = session.get('signup_data')
    if not signup_data or not signup_data.get('key_verified'):
        return redirect(url_for('signup_step1_email'))

    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup_step3_details'))

        if User.query.filter_by(username=username).first():
            flash('That username is already taken. Please choose another.', 'warning')
            return redirect(url_for('signup_step3_details'))
        if User.query.filter_by(email=signup_data['email']).first():
            flash('An account with this email already exists.', 'warning')
            return redirect(url_for('login'))

        company = Company.query.filter_by(name=signup_data['company_name']).first()
        if not company:
            company = Company(
                name=signup_data['company_name'],
                user_limit=signup_data['users_allowed']
            )
            db.session.add(company)
            db.session.flush()
            create_default_roles_and_permissions(company.id)
        else:
            user_count = User.query.filter_by(company_id=company.id).count()
            if user_count >= company.user_limit:
                flash('The maximum number of users for your organization has been reached.', 'danger')
                return redirect(url_for('login'))

        admin_role = Role.query.filter_by(company_id=company.id, name='Admin').first()
        if not admin_role:
            flash('Critical error: Admin role not found for company.', 'danger')
            return redirect(url_for('login'))

        new_user = User(
            company_id=company.id,
            role_id=admin_role.id,
            username=username,
            email=signup_data['email'],
            first_name=first_name,
            last_name=last_name
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        session.pop('signup_data', None)
        flash('Your account has been created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup/step3_details.html', data=signup_data, hide_sidebar=True)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

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
    if role.company_id != current_user.company_id:
        abort(403)
    if role.is_admin:
        flash('The default Admin role cannot be modified.', 'warning')
        return redirect(url_for('manage_roles'))

    if request.method == 'POST':
        role.name = request.form.get('name')
        role.description = request.form.get('description')
        
        selected_permission_ids = request.form.getlist('permissions')
        role.permissions = Permission.query.filter(Permission.id.in_(selected_permission_ids)).all()
        
        db.session.commit()
        flash(f'Role "{role.name}" has been updated.', 'success')
        return redirect(url_for('manage_roles'))

    all_permissions = Permission.query.all()
    return render_template('roles/edit_role.html', role=role, all_permissions=all_permissions)

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

def get_form_data():
    """Helper to fetch data for the equipment form dropdowns."""
    company_id = current_user.company_id
    return {
        'categories': Category.query.filter_by(company_id=company_id, is_active=True).all(),
        'locations': Location.query.filter_by(company_id=company_id, is_active=True).all(),
        'departments': Department.query.filter_by(company_id=company_id, is_active=True).all(),
        'vendors': Vendor.query.filter_by(company_id=company_id).order_by(Vendor.name).all() # <-- ADD THIS LINE
    }

@app.route('/equipment/add', methods=['GET', 'POST'])
@login_required
@permission_required('CAN_MANAGE_EQUIPMENT')
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
            new_equip.images = saved_files['images'] or None
            new_equip.videos = saved_files['videos'] or None
            new_equip.audio_files = saved_files['audio_files'] or None
            new_equip.documents = saved_files['documents'] or None

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
@permission_required('CAN_MANAGE_EQUIPMENT') # Or a new 'CAN_VIEW_EQUIPMENT' permission if you prefer
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
@permission_required('CAN_MANAGE_EQUIPMENT')
def edit_equipment(equip_id):
    equipment = Equipment.query.get_or_404(equip_id)
    
    if equipment.company_id != current_user.company_id:
        abort(403)

    if request.method == 'POST':
        save_actions = [] # Initialize here
        try:
            # Step 1: Update text-based fields
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

            # Step 2: Handle new file uploads using the new helper
            save_actions = process_uploads(equipment, request.files, 'equipment')
            
            # Step 3: Flag modified fields for SQLAlchemy
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(equipment, "images")
            flag_modified(equipment, "videos")
            flag_modified(equipment, "audio_files")
            flag_modified(equipment, "documents")

            # --- Transactional Logic ---
            db.session.commit() # Commit DB changes first

            for file, save_path in save_actions: # Run file saves only after successful commit
                file.save(save_path)

            flash(f'Equipment "{equipment.name}" updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the equipment: {e}', 'danger')
            print(f"Error in edit_equipment: {e}") # For debugging

        return redirect(url_for('manage_equipment'))

    return render_template('equipment/form.html', equipment=equipment, form_data=get_form_data())

@app.route('/equipment/delete/<int:equip_id>', methods=['POST'])
@login_required
@permission_required('CAN_MANAGE_EQUIPMENT')
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
@permission_required('CAN_MANAGE_EQUIPMENT')
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
@permission_required('CAN_MANAGE_INVENTORY')
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
@permission_required('CAN_MANAGE_INVENTORY')
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
            new_item.images = saved_files['images'] or None
            new_item.videos = saved_files['videos'] or None
            new_item.audio_files = saved_files['audio_files'] or None
            new_item.documents = saved_files['documents'] or None
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
@permission_required('CAN_MANAGE_INVENTORY')
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
@permission_required('CAN_MANAGE_INVENTORY')
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
@permission_required('CAN_MANAGE_INVENTORY')
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
@permission_required('CAN_MANAGE_VENDORS')
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
@permission_required('CAN_MANAGE_VENDORS')
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
            new_vendor.images = saved_files['images'] or None
            new_vendor.videos = saved_files['videos'] or None
            new_vendor.audio_files = saved_files['audio_files'] or None
            new_vendor.documents = saved_files['documents'] or None
            
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
@permission_required('CAN_MANAGE_VENDORS')
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
@permission_required('CAN_MANAGE_VENDORS')
def delete_vendor(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    if vendor.company_id != current_user.company_id:
        abort(403)
    
    delete_all_uploads(vendor, 'vendors')
    db.session.delete(vendor)
    db.session.commit()
    flash(f'Vendor "{vendor.name}" has been deleted.', 'success')
    return redirect(url_for('manage_vendors'))

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

if __name__ == '__main__':
    app.run(debug=True, port=8080)