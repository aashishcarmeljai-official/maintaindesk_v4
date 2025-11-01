from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime, timezone
from sqlalchemy.dialects.postgresql import JSONB
from flask import current_app
from itsdangerous import URLSafeTimedSerializer as Serializer

db = SQLAlchemy()
bcrypt = Bcrypt()

# Association table for the many-to-many relationship between Role and Permission
roles_permissions = db.Table('roles_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

class Permission(db.Model):
    """Represents a specific action a user can perform (e.g., 'CAN_MANAGE_USERS')."""
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class Company(db.Model):
    """Represents a company or organization in the system."""
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    user_limit = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    users = db.relationship('User', backref='company', lazy=True)
    roles = db.relationship('Role', backref='company', lazy=True)

class Role(db.Model):
    """Represents user roles within a company (e.g., Admin, Manager)."""
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    level = db.Column(db.Integer, nullable=False, default=99)

    # The many-to-many relationship to Permissions
    permissions = db.relationship('Permission', secondary=roles_permissions,
                                  lazy='subquery', backref=db.backref('roles', lazy=True))
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    """Represents a user account in the system."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    department = db.relationship('Department', backref=db.backref('users', lazy=True))
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    password_reset_required = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def get_reset_token(self, expires_sec=1800):
        """Generates a secure, timed token for password reset."""
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        """Verifies a password reset token and returns the user if valid."""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
        except:
            return None
        return User.query.get(user_id)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Location(db.Model):
    """Represents a physical or logical location for a company."""
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    country = db.Column(db.String(100))
    state = db.Column(db.String(100))
    city = db.Column(db.String(100))
    zip_code = db.Column(db.String(20))
    description = db.Column(db.Text)
    contact_person = db.Column(db.String(100))
    contact_phone = db.Column(db.String(50))
    contact_email = db.Column(db.String(120))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Add a relationship back to the Company
    company = db.relationship('Company', backref=db.backref('locations', lazy=True))
    
class Category(db.Model):
    """Represents categories for assets like Equipment or Inventory."""
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    category_type = db.Column(db.String(50), nullable=False)  # "Equipment" or "Inventory"
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    color = db.Column(db.String(7), nullable=False, default='#3f8efc') # Stores hex color
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Add a relationship back to the Company
    company = db.relationship('Company', backref=db.backref('categories', lazy=True))
    
class Department(db.Model):
    """Represents company departments like Maintenance, Production, etc."""
    __tablename__ = 'departments'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Add a relationship back to the Company
    company = db.relationship('Company', backref=db.backref('departments', lazy=True))
    
class Equipment(db.Model):
    """Represents a piece of equipment."""
    __tablename__ = 'equipment'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    
    # Basic Information
    name = db.Column(db.String(255), nullable=False)
    equipment_id = db.Column(db.String(100), unique=True, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    criticality = db.Column(db.String(50)) # Low, Medium, High, Critical

    # Technical Details
    manufacturer_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=True)
    model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    purchase_date = db.Column(db.Date)
    warranty_expiry_date = db.Column(db.Date)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    
    # Description & Specs
    description = db.Column(db.Text)
    specifications = db.Column(db.Text)
    
    images = db.Column(JSONB) # Stores a list of image filenames
    videos = db.Column(JSONB) # Stores a list of video filenames
    audio_files = db.Column(JSONB) # Stores a list of audio filenames
    documents = db.Column(JSONB) # Stores a list of document filenames

    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    company = db.relationship('Company', backref=db.backref('equipment', lazy=True))
    category = db.relationship('Category', backref=db.backref('equipment', lazy=True))
    location = db.relationship('Location', backref=db.backref('equipment', lazy=True))
    department = db.relationship('Department', backref=db.backref('equipment', lazy=True))
    manufacturer = db.relationship('Vendor', foreign_keys=[manufacturer_id], backref=db.backref('manufactured_equipment', lazy=True))
    meters = db.relationship('Meter', backref='equipment', lazy='dynamic', cascade="all, delete-orphan")
    
class Unit(db.Model):
    """Represents a unit of measurement (e.g., meter, kilogram)."""
    __tablename__ = 'units'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    symbol = db.Column(db.String(20))
    
    # Self-referencing relationship for base units
    base_unit_id = db.Column(db.Integer, db.ForeignKey('units.id'), nullable=True)
    conversion_factor = db.Column(db.Float, nullable=True)

    company = db.relationship('Company', backref=db.backref('units', lazy=True))
    base_unit = db.relationship('Unit', remote_side=[id], backref='derived_units')
    
class Currency(db.Model):
    """Represents a currency (e.g., US Dollar)."""
    __tablename__ = 'currencies'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(3), nullable=False)  # e.g., USD
    symbol = db.Column(db.String(5))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_default = db.Column(db.Boolean, default=False, nullable=False)

    company = db.relationship('Company', backref=db.backref('currencies', lazy=True))
    
class InventoryItem(db.Model):
    """Represents an item in the inventory."""
    __tablename__ = 'inventory_items'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)

    # Basic Information
    name = db.Column(db.String(255), nullable=False)
    part_number = db.Column(db.String(100), unique=True, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    description = db.Column(db.Text)

    # Supplier Information
    unit_cost = db.Column(db.Numeric(10, 2))
    currency_id = db.Column(db.Integer, db.ForeignKey('currencies.id'))
    unit_of_measure_id = db.Column(db.Integer, db.ForeignKey('units.id'))

    # Stock Management
    current_stock = db.Column(db.Integer, default=0)
    minimum_stock = db.Column(db.Integer, nullable=False, default=0)
    maximum_stock = db.Column(db.Integer)
    
    manufacturer_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=True)
    
    # Storage
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))
    
    images = db.Column(JSONB)
    videos = db.Column(JSONB)
    audio_files = db.Column(JSONB)
    documents = db.Column(JSONB)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    company = db.relationship('Company', backref=db.backref('inventory_items', lazy=True))
    category = db.relationship('Category', backref=db.backref('inventory_items', lazy=True))
    department = db.relationship('Department', backref=db.backref('inventory_items', lazy=True))
    currency = db.relationship('Currency', backref=db.backref('inventory_items', lazy=True))
    unit_of_measure = db.relationship('Unit', backref=db.backref('inventory_items', lazy=True))
    location = db.relationship('Location', backref=db.backref('inventory_items', lazy=True))
    manufacturer = db.relationship('Vendor', foreign_keys=[manufacturer_id], backref='manufactured_inventory')
    supplier = db.relationship('Vendor', foreign_keys=[supplier_id], backref='supplied_inventory')

class Vendor(db.Model):
    """Represents a supplier or vendor."""
    __tablename__ = 'vendors'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))
    
    # Media files
    images = db.Column(JSONB)
    videos = db.Column(JSONB)
    audio_files = db.Column(JSONB)
    documents = db.Column(JSONB)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    company = db.relationship('Company', backref=db.backref('vendors', lazy=True))
    location = db.relationship('Location', backref=db.backref('vendors', lazy=True))
    contacts = db.relationship('VendorContact', backref='vendor', lazy=True, cascade="all, delete-orphan")

class VendorContact(db.Model):
    """Represents a contact person for a vendor."""
    __tablename__ = 'vendor_contacts'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    position = db.Column(db.String(100))
    
team_members = db.Table('team_members',
    db.Column('team_id', db.Integer, db.ForeignKey('teams.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

class Team(db.Model):
    """Represents a team of users."""
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    company = db.relationship('Company', backref=db.backref('teams', lazy=True))
    members = db.relationship('User', secondary=team_members, lazy='subquery',
                              backref=db.backref('teams', lazy=True))
    
class NotificationLog(db.Model):
    """Stores a log of flash messages shown to users."""
    __tablename__ = 'notification_logs'
    id = db.Column(db.Integer, primary_key=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True, cascade="all, delete-orphan"))
    
class WorkOrder(db.Model):
    """Represents a work order."""
    __tablename__ = 'work_orders'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    
    # Core Details
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(50), default='Medium') # Low, Medium, High, Urgent
    status = db.Column(db.String(50), default='Open', nullable=False) # On Hold, Open, In Progress, Completed, Rejected
    work_order_type = db.Column(db.String(50)) # Corrective, Preventive, Emergency
    
    # Guest Data
    guest_reporter_name = db.Column(db.String(100), nullable=True)
    guest_reporter_email = db.Column(db.String(120), nullable=True)
    
    # Dates
    scheduled_date = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime)
    estimated_duration = db.Column(db.Integer) # in minutes
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)

    # Relationships
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_to_team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    
    # For approval workflow
    is_approved = db.Column(db.Boolean, default=False)
    rejection_reason = db.Column(db.Text)

    # Media
    images = db.Column(JSONB)
    videos = db.Column(JSONB)
    audio_files = db.Column(JSONB)
    documents = db.Column(JSONB)

    # SQLAlchemy Relationships
    company = db.relationship('Company', backref='work_orders')
    equipment = db.relationship('Equipment', backref='work_orders')
    location = db.relationship('Location', backref='work_orders')
    created_by = db.relationship('User', foreign_keys=[created_by_id], backref='created_work_orders')
    assigned_user = db.relationship('User', foreign_keys=[assigned_to_user_id], backref='assigned_work_orders')
    assigned_team = db.relationship('Team', foreign_keys=[assigned_to_team_id], backref='work_orders')
    
class MqttConfig(db.Model):
    """Stores MQTT broker configuration for a company."""
    __tablename__ = 'mqtt_configs'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), unique=True, nullable=False)
    
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=1883, nullable=False)
    username = db.Column(db.String(100))
    password = db.Column(db.String(100)) # In a real app, encrypt this!
    
    company = db.relationship('Company', backref=db.backref('mqtt_config', uselist=False, cascade="all, delete-orphan"))
    
class Meter(db.Model):
    """Represents an IoT meter or sensor that publishes data to MQTT."""
    __tablename__ = 'meters'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    mqtt_topic = db.Column(db.String(255), nullable=False, unique=True) # Topics must be unique
    
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))
    
    images = db.Column(JSONB)
    videos = db.Column(JSONB)
    audio_files = db.Column(JSONB)
    documents = db.Column(JSONB)
    
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    company = db.relationship('Company', backref=db.backref('meters', lazy=True))
    location = db.relationship('Location', backref=db.backref('meters', lazy=True))
    readings = db.relationship('MeterReading', backref='meter', lazy='dynamic', cascade="all, delete-orphan")
    
class MeterReading(db.Model):
    """Stores a single time-series reading from a Meter."""
    __tablename__ = 'meter_readings'
    id = db.Column(db.Integer, primary_key=True)
    
    meter_id = db.Column(db.Integer, db.ForeignKey('meters.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    
    # Use JSONB to store the variable data from the sensor payload
    value = db.Column(JSONB, nullable=False)