from datetime import date, datetime, timedelta
from functools import wraps
import os

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

app = Flask(__name__)
app.config.from_object("config.Config")
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
csrf = CSRFProtect(app)

# ----------------------------- DATABASE MODELS -----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="SalesExecutive")
    active = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_code = db.Column(db.String(30), unique=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    company = db.Column(db.String(120))
    address = db.Column(db.String(250))
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    status = db.Column(db.String(30), default="Active")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_code = db.Column(db.String(30), unique=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    company = db.Column(db.String(120))
    source = db.Column(db.String(60), default="Website")
    status = db.Column(db.String(30), default="New")
    priority = db.Column(db.String(20), default="Medium")
    expected_value = db.Column(db.Float, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    customer_name = db.Column(db.String(100))
    amount = db.Column(db.Float, nullable=False)
    probability = db.Column(db.Integer, nullable=False, default=25)
    stage = db.Column(db.String(30), default="Qualification")
    expected_close_date = db.Column(db.Date, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FollowUp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(120), nullable=False)
    related_to = db.Column(db.String(120))
    follow_up_date = db.Column(db.Date, nullable=False)
    follow_up_type = db.Column(db.String(30), default="Call")
    status = db.Column(db.String(30), default="Planned")
    notes = db.Column(db.String(500))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_type = db.Column(db.String(30), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500))
    activity_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(30), default="Planned")
    related_to = db.Column(db.String(120))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    user_email = db.Column(db.String(120))
    action = db.Column(db.String(40), nullable=False)
    entity = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer)
    details = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(60))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def audit(action, entity, record_id=None, details=""):
    db.session.add(AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        user_email=current_user.email if current_user.is_authenticated else "anonymous",
        action=action, entity=entity, record_id=record_id, details=details,
        ip_address=request.remote_addr
    ))

def roles_required(*roles):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return func(*args, **kwargs)
        return wrapped
    return decorator

def can_access(record):
    return current_user.role in ("Admin", "Manager") or record.owner_id == current_user.id

def scoped_query(model):
    q = model.query
    if current_user.role == "SalesExecutive":
        q = q.filter_by(owner_id=current_user.id)
    return q

def valid_email(value):
    import re
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value or ""))

def valid_phone(value):
    import re
    return bool(re.fullmatch(r"[0-9+\-\s()]{10,15}", value or ""))

# ----------------------------- AUTHENTICATION -------------------------------
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, message="Use at least 8 characters.")])
    submit = SubmitField("Create account")

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        now = datetime.utcnow()
        if user and user.lockout_until and user.lockout_until > now:
            flash("Account temporarily locked. Try again later.", "danger")
        elif user and user.active and user.check_password(form.password.data):
            user.failed_attempts = 0
            user.lockout_until = None
            login_user(user)
            audit("LOGIN", "Authentication", user.id, "Successful login")
            db.session.commit()
            return redirect(url_for("dashboard"))
        else:
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= 5:
                    user.lockout_until = now + timedelta(minutes=10)
                audit("FAILED_LOGIN", "Authentication", user.id, "Invalid credentials or inactive account")
                db.session.commit()
            flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        if User.query.filter_by(email=email).first():
            flash("That email is already registered.", "warning")
        else:
            user = User(name=form.name.data.strip(), email=email, role="SalesExecutive")
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.flush()
            audit("REGISTER", "User", user.id, "Self-registration as SalesExecutive")
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/logout")
@login_required
def logout():
    audit("LOGOUT", "Authentication", current_user.id, "User logged out")
    db.session.commit()
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# -------------------------------- DASHBOARD ---------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    models = [Customer, Lead, Opportunity, FollowUp, Activity]
    counts = {}
    for model in models:
        counts[model.__name__] = scoped_query(model).count()
    opportunities = scoped_query(Opportunity).all()
    open_opps = [o for o in opportunities if o.stage not in ("Won", "Lost")]
    pipeline = sum(o.amount for o in open_opps)
    lead_statuses = ["New", "Contacted", "Qualified", "Lost", "Converted"]
    lead_counts = [scoped_query(Lead).filter_by(status=s).count() for s in lead_statuses]
    stages = ["Qualification", "Proposal", "Negotiation", "Won", "Lost"]
    stage_counts = [scoped_query(Opportunity).filter_by(stage=s).count() for s in stages]
    upcoming = scoped_query(FollowUp).filter(FollowUp.follow_up_date >= date.today()).order_by(FollowUp.follow_up_date).limit(5).all()
    return render_template("dashboard.html", counts=counts, pipeline=pipeline,
                           lead_statuses=lead_statuses, lead_counts=lead_counts,
                           stages=stages, stage_counts=stage_counts, upcoming=upcoming)

# ----------------------------- GENERIC CRUD --------------------------------
RESOURCES = {
    "customers": {
        "model": Customer, "title": "Customers",
        "fields": [
            ("name", "Customer name", "text", True), ("email", "Email", "email", True),
            ("phone", "Phone", "text", True), ("company", "Company", "text", False),
            ("address", "Address", "text", False), ("city", "City", "text", False),
            ("state", "State", "text", False), ("status", "Status", "select:Active,Inactive", True)
        ],
        "search": ["name", "email", "phone", "company"]
    },
    "leads": {
        "model": Lead, "title": "Leads",
        "fields": [
            ("name", "Lead name", "text", True), ("email", "Email", "email", False),
            ("phone", "Phone", "text", False), ("company", "Company", "text", False),
            ("source", "Source", "select:Website,Referral,Advertisement,Social Media,Other", True),
            ("status", "Status", "select:New,Contacted,Qualified,Unqualified,Converted,Lost", True),
            ("priority", "Priority", "select:Low,Medium,High", True),
            ("expected_value", "Expected value", "number", False)
        ], "search": ["name", "company", "status"]
    },
    "opportunities": {
        "model": Opportunity, "title": "Opportunities",
        "fields": [
            ("name", "Opportunity name", "text", True), ("customer_name", "Customer", "text", False),
            ("amount", "Amount", "number", True), ("probability", "Probability (0-100)", "number", True),
            ("stage", "Stage", "select:Qualification,Proposal,Negotiation,Won,Lost", True),
            ("expected_close_date", "Expected close date", "date", True)
        ], "search": ["name", "customer_name", "stage"]
    },
    "followups": {
        "model": FollowUp, "title": "Follow-ups",
        "fields": [
            ("subject", "Subject", "text", True), ("related_to", "Related customer/lead", "text", False),
            ("follow_up_date", "Follow-up date", "date", True),
            ("follow_up_type", "Type", "select:Call,Meeting,Email,Task", True),
            ("status", "Status", "select:Planned,Completed,Missed,Cancelled", True),
            ("notes", "Notes", "textarea", False)
        ], "search": ["subject", "related_to", "status"]
    },
    "activities": {
        "model": Activity, "title": "Activities",
        "fields": [
            ("activity_type", "Activity type", "select:Call,Meeting,Email,Task", True),
            ("subject", "Subject", "text", True), ("description", "Description", "textarea", False),
            ("activity_date", "Activity date", "date", True),
            ("status", "Status", "select:Planned,Completed,Cancelled", True),
            ("related_to", "Related customer/lead", "text", False)
        ], "search": ["subject", "activity_type", "status", "related_to"]
    }
}

def parse_value(field_type, value):
    if field_type == "number":
        if value == "":
            return 0
        return float(value)
    if field_type == "date":
        return datetime.strptime(value, "%Y-%m-%d").date()
    return value.strip() if isinstance(value, str) else value

def validate_resource(key, data):
    errors = []
    cfg = RESOURCES[key]
    for name, label, typ, required in cfg["fields"]:
        value = data.get(name, "").strip() if isinstance(data.get(name, ""), str) else data.get(name, "")
        if required and value == "":
            errors.append(f"{label} is required.")
        if name == "email" and value and not valid_email(value):
            errors.append("Enter a valid email address.")
        if name == "phone" and value and not valid_phone(value):
            errors.append("Enter a valid phone number (10-15 allowed characters).")
        if name == "name" and len(str(value)) > 100:
            errors.append(f"{label} must be 100 characters or fewer.")
        if key == "customers" and name in ("email", "phone") and value:
            existing = Customer.query.filter(getattr(Customer, name) == value).first()
            if existing and str(existing.id) != str(data.get("record_id", "")):
                errors.append(f"Customer {name} must be unique.")
        if key == "opportunities":
            if name == "amount" and value != "" and float(value) <= 0:
                errors.append("Opportunity Amount must be greater than 0.")
            if name == "probability" and value != "" and not 0 <= int(value) <= 100:
                errors.append("Probability must be between 0 and 100.")
            if name == "expected_close_date" and value and value < date.today().isoformat() and data.get("stage") not in ("Won", "Lost"):
                errors.append("Expected Close Date cannot be in the past.")
        if key == "followups" and name == "follow_up_date" and value and value < date.today().isoformat() and data.get("status") == "Planned":
            errors.append("Follow-up date cannot be earlier than today.")
    return errors

@app.route("/<key>")
@login_required
def list_resource(key):
    if key not in RESOURCES:
        abort(404)
    cfg = RESOURCES[key]
    q = scoped_query(cfg["model"])
    term = request.args.get("q", "").strip()
    if term:
        q = q.filter(or_(*[getattr(cfg["model"], f).ilike(f"%{term}%") for f in cfg["search"]]))
    records = q.order_by(cfg["model"].id.desc()).all()
    return render_template("list.html", key=key, cfg=cfg, records=records, term=term)

@app.route("/<key>/new", methods=["GET", "POST"])
@login_required
def create_resource(key):
    if key not in RESOURCES: abort(404)
    cfg = RESOURCES[key]
    if request.method == "POST":
        errors = validate_resource(key, request.form)
        if errors:
            for e in errors: flash(e, "danger")
        else:
            obj = cfg["model"]()
            for name, label, typ, required in cfg["fields"]:
                raw = request.form.get(name, "")
                setattr(obj, name, parse_value(typ.split(":")[0], raw))
            obj.owner_id = current_user.id
            if key == "customers":
                obj.customer_code = f"CUS-{datetime.utcnow():%y%m%d%H%M%S}"
            if key == "leads":
                obj.lead_code = f"LED-{datetime.utcnow():%y%m%d%H%M%S}"
            db.session.add(obj)
            db.session.flush()
            audit("CREATE", cfg["title"], obj.id, f"Created {cfg['title'][:-1]}")
            db.session.commit()
            flash(f"{cfg['title'][:-1]} created successfully.", "success")
            return redirect(url_for("list_resource", key=key))
    return render_template("form.html", key=key, cfg=cfg, record=None)

@app.route("/<key>/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
def edit_resource(key, record_id):
    if key not in RESOURCES: abort(404)
    cfg = RESOURCES[key]
    obj = db.session.get(cfg["model"], record_id) or abort(404)
    if not can_access(obj): abort(403)
    if request.method == "POST":
        data = request.form.to_dict()
        data["record_id"] = record_id
        errors = validate_resource(key, data)
        if errors:
            for e in errors: flash(e, "danger")
        else:
            for name, label, typ, required in cfg["fields"]:
                setattr(obj, name, parse_value(typ.split(":")[0], request.form.get(name, "")))
            audit("UPDATE", cfg["title"], obj.id, f"Updated {cfg['title'][:-1]}")
            db.session.commit()
            flash("Record updated successfully.", "success")
            return redirect(url_for("list_resource", key=key))
    return render_template("form.html", key=key, cfg=cfg, record=obj)

@app.route("/<key>/<int:record_id>/delete", methods=["POST"])
@login_required
def delete_resource(key, record_id):
    if key not in RESOURCES: abort(404)
    if current_user.role != "Admin": abort(403)
    cfg = RESOURCES[key]
    obj = db.session.get(cfg["model"], record_id) or abort(404)
    audit("DELETE", cfg["title"], obj.id, f"Deleted {cfg['title'][:-1]}")
    db.session.delete(obj)
    db.session.commit()
    flash("Record deleted.", "success")
    return redirect(url_for("list_resource", key=key))

# -------------------------------- USERS -------------------------------------
@app.route("/users")
@roles_required("Admin")
def users():
    return render_template("users.html", users=User.query.order_by(User.id.desc()).all())

@app.route("/users/<int:user_id>/role", methods=["POST"])
@roles_required("Admin")
def change_role(user_id):
    user = db.session.get(User, user_id) or abort(404)
    role = request.form.get("role")
    if role not in ("Admin", "Manager", "SalesExecutive"):
        abort(400)
    old = user.role
    user.role = role
    audit("ROLE_CHANGE", "User", user.id, f"{old} -> {role}")
    db.session.commit()
    flash("User role updated.", "success")
    return redirect(url_for("users"))

@app.route("/audit")
@roles_required("Admin", "Manager")
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(300).all()
    if current_user.role == "Manager":
        logs = [x for x in logs if x.user_id == current_user.id]
    return render_template("audit.html", logs=logs)

# -------------------------------- REST API ----------------------------------
@app.route("/api/customers", methods=["GET", "POST"])
@login_required
def api_customers():
    if request.method == "GET":
        records = scoped_query(Customer).all()
        return jsonify([{"id":x.id,"name":x.name,"email":x.email,"phone":x.phone,"company":x.company,"status":x.status} for x in records])
    data = request.get_json(silent=True) or {}
    errors = []
    if not data.get("name"): errors.append("Customer name is required.")
    if not valid_email(data.get("email", "")): errors.append("Valid email is required.")
    if not valid_phone(data.get("phone", "")): errors.append("Valid phone is required.")
    if Customer.query.filter_by(email=data.get("email")).first(): errors.append("Email already exists.")
    if Customer.query.filter_by(phone=data.get("phone")).first(): errors.append("Phone already exists.")
    if errors: return jsonify({"errors":errors}), 400
    obj = Customer(name=data["name"], email=data["email"], phone=data["phone"],
                   company=data.get("company",""), status=data.get("status","Active"),
                   owner_id=current_user.id)
    db.session.add(obj); db.session.flush()
    audit("CREATE", "Customer(API)", obj.id, "Created through API")
    db.session.commit()
    return jsonify({"id":obj.id,"name":obj.name}), 201

@app.route("/api/customers/<int:record_id>", methods=["GET", "PUT", "DELETE"])
@login_required
def api_customer_detail(record_id):
    obj = db.session.get(Customer, record_id) or abort(404)
    if not can_access(obj): abort(403)
    if request.method == "GET":
        return jsonify({"id":obj.id,"name":obj.name,"email":obj.email,"phone":obj.phone,"company":obj.company,"status":obj.status})
    if request.method == "DELETE":
        audit("DELETE", "Customer(API)", obj.id, "Deleted through API")
        db.session.delete(obj); db.session.commit()
        return "", 204
    data = request.get_json(silent=True) or {}
    for field in ("name","email","phone","company","status"):
        if field in data: setattr(obj, field, data[field])
    if not obj.name or not valid_email(obj.email) or not valid_phone(obj.phone):
        return jsonify({"error":"Invalid customer data."}), 400
    audit("UPDATE", "Customer(API)", obj.id, "Updated through API")
    db.session.commit()
    return jsonify({"id":obj.id,"name":obj.name})

@app.route("/api/leads", methods=["GET", "POST"])
@login_required
def api_leads():
    if request.method == "GET":
        return jsonify([{"id":x.id,"name":x.name,"status":x.status,"source":x.source} for x in scoped_query(Lead).all()])
    data = request.get_json(silent=True) or {}
    if not data.get("name"): return jsonify({"error":"Lead name is required."}), 400
    status = data.get("status","New")
    if status not in ("New","Contacted","Qualified","Unqualified","Converted","Lost"):
        return jsonify({"error":"Invalid lead status."}), 400
    obj = Lead(name=data["name"], email=data.get("email"), phone=data.get("phone"),
               company=data.get("company"), source=data.get("source","Website"),
               status=status, owner_id=current_user.id)
    db.session.add(obj); db.session.flush()
    audit("CREATE", "Lead(API)", obj.id, "Created through API")
    db.session.commit()
    return jsonify({"id":obj.id,"name":obj.name}), 201

@app.route("/api/opportunities", methods=["GET", "POST"])
@login_required
def api_opportunities():
    if request.method == "GET":
        return jsonify([{"id":x.id,"name":x.name,"amount":x.amount,"stage":x.stage,"probability":x.probability} for x in scoped_query(Opportunity).all()])
    data = request.get_json(silent=True) or {}
    try:
        amount = float(data.get("amount", 0))
        probability = int(data.get("probability", 0))
        close_date = datetime.strptime(data.get("expected_close_date",""), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return jsonify({"error":"Amount, probability and expected_close_date are required in valid formats."}), 400
    if not data.get("name") or amount <= 0 or not 0 <= probability <= 100:
        return jsonify({"error":"Name is required, amount must be greater than 0 and probability must be 0-100."}), 400
    if close_date < date.today() and data.get("stage","Qualification") not in ("Won","Lost"):
        return jsonify({"error":"Expected close date cannot be in the past."}), 400
    obj = Opportunity(name=data["name"], customer_name=data.get("customer_name"),
        amount=amount, probability=probability, stage=data.get("stage","Qualification"),
        expected_close_date=close_date, owner_id=current_user.id)
    db.session.add(obj); db.session.flush()
    audit("CREATE", "Opportunity(API)", obj.id, "Created through API")
    db.session.commit()
    return jsonify({"id":obj.id,"name":obj.name}), 201

# -------------------------------- ERROR PAGES -------------------------------
@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The requested page or record was not found."), 404

# -------------------------------- INITIALIZE --------------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@acxiomcrm.local").first():
        admin = User(name="System Admin", email="admin@acxiomcrm.local", role="Admin", active=True)
        admin.set_password("Admin@12345")
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)
