
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re
import joblib

# Import detection modules
from app.url_checker import check_url
from app.email_checker import check_email


app = Flask(__name__)

app.config["SECRET_KEY"] = "change-this-secret-key-before-deployment"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scam_detection.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ADMIN ACCOUNT
ADMIN_EMAIL = "sgsanjanapoojary2006@gmail.com"


# LOAD MACHINE LEARNING MODEL

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR, "models", "scam_message_model.pkl"
)

model = joblib.load(MODEL_PATH)


# DATABASE MODELS

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


class PhoneReport(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    phone_number = db.Column(
        db.String(15),
        nullable=False,
        index=True
    )

    category = db.Column(
        db.String(50),
        nullable=False
    )

    description = db.Column(
        db.String(1000),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    reporter = db.relationship(
        "User",
        backref="phone_reports"
    )


# GENERAL SCAM REPORT MODEL

class ScamReport(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    report_type = db.Column(
        db.String(30),
        nullable=False
    )

    target = db.Column(
        db.String(500),
        nullable=False
    )

    category = db.Column(
        db.String(100),
        nullable=False
    )

    description = db.Column(
        db.String(1000),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    status = db.Column(
        db.String(30),
        default="Pending"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    reporter = db.relationship(
        "User",
        backref="scam_reports"
    )


@login_manager.user_loader
def load_user(user_id):

    return db.session.get(User, int(user_id))


# HOME

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# REGISTRATION

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:

            flash("Please fill in all fields.", "danger")
            return redirect(url_for("register"))

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "danger"
            )
            return redirect(url_for("register"))

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )
            return redirect(url_for("register"))

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:

            flash(
                "Username or email already registered.",
                "danger"
            )
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )

        db.session.add(new_user)
        db.session.commit()

        flash(
            "Registration successful! Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            login_user(user)

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


# DASHBOARD WITH RISK ANALYSIS STATISTICS

@app.route("/dashboard")
@login_required
def dashboard():

    scam_reports = ScamReport.query.filter_by(
        user_id=current_user.id
    ).all()

    phone_reports = PhoneReport.query.filter_by(
        user_id=current_user.id
    ).all()

    total_scam_reports = len(scam_reports)
    total_phone_reports = len(phone_reports)

    total_reports = total_scam_reports + total_phone_reports

    pending_reports = ScamReport.query.filter_by(
        user_id=current_user.id,
        status="Pending"
    ).count()

    phone_count = sum(
        1 for report in scam_reports
        if report.report_type == "Phone"
    ) + total_phone_reports

    url_count = sum(
        1 for report in scam_reports
        if report.report_type == "URL"
    )

    message_count = sum(
        1 for report in scam_reports
        if report.report_type == "Message"
    )

    email_count = sum(
        1 for report in scam_reports
        if report.report_type == "Email"
    )

    return render_template(
        "dashboard.html",
        username=current_user.username,
        total_reports=total_reports,
        pending_reports=pending_reports,
        phone_count=phone_count,
        url_count=url_count,
        message_count=message_count,
        email_count=email_count
    )


# AI SCAM MESSAGE DETECTION

@app.route("/message-check", methods=["GET", "POST"])
@login_required
def message_check():

    result = None
    checked_message = ""

    if request.method == "POST":

        checked_message = request.form.get(
            "message", ""
        ).strip()

        if not checked_message:

            flash(
                "Please enter a message to check.",
                "danger"
            )

        elif len(checked_message) > 5000:

            flash(
                "Message is too long. Maximum 5000 characters.",
                "danger"
            )

        else:

            prediction = model.predict([checked_message])[0]

            probabilities = model.predict_proba(
                [checked_message]
            )[0]

            classes = list(model.classes_)

            scam_probability = float(
                probabilities[classes.index("scam")]
            )

            if scam_probability >= 0.70:

                risk = "High Risk"
                risk_color = "danger"

            elif scam_probability >= 0.40:

                risk = "Medium Risk"
                risk_color = "warning"

            else:

                risk = "Low Risk"
                risk_color = "success"

            result = {
                "prediction": prediction,
                "risk": risk,
                "risk_color": risk_color,
                "score": round(
                    scam_probability * 100, 2
                )
            }

    return render_template(
        "message_checker.html",
        result=result,
        checked_message=checked_message
    )


# URL PHISHING DETECTION

@app.route("/url-check", methods=["GET", "POST"])
@login_required
def url_check():

    result = None
    checked_url = ""

    if request.method == "POST":

        checked_url = request.form.get(
            "url", ""
        ).strip()

        if not checked_url:

            flash("Please enter a URL.", "danger")

        elif len(checked_url) > 2048:

            flash("URL is too long.", "danger")

        else:

            result = check_url(checked_url)

    return render_template(
        "url_checker.html",
        result=result,
        checked_url=checked_url
    )


# EMAIL SCAM DETECTION

@app.route("/email-check", methods=["GET", "POST"])
@login_required
def email_check():

    result = None
    checked_email = ""

    if request.method == "POST":

        checked_email = request.form.get(
            "email_text", ""
        ).strip()

        if not checked_email:

            flash(
                "Please paste an email to check.",
                "danger"
            )

        elif len(checked_email) > 10000:

            flash(
                "Email is too long. Maximum 10000 characters.",
                "danger"
            )

        else:

            result = check_email(checked_email)

    return render_template(
        "email_checker.html",
        result=result,
        checked_email=checked_email
    )


# PHONE NUMBER NORMALIZATION

def normalize_phone(phone):

    return re.sub(r"\D", "", phone)


# PHONE NUMBER CHECKER WITH RISK ANALYSIS

@app.route("/phone-check", methods=["GET", "POST"])
@login_required
def phone_check():

    phone = ""
    reports = []
    total_reports = 0
    category_summary = []

    risk = "Unrated"
    risk_score = None
    risk_color = "secondary"

    risk_message = (
        "No community reports found. This number cannot be "
        "confirmed safe or unsafe."
    )

    if request.method == "POST":

        phone = request.form.get(
            "phone", ""
        ).strip()

        normalized_phone = normalize_phone(phone)

        if not normalized_phone:

            flash(
                "Please enter a phone number.",
                "danger"
            )

        elif not 7 <= len(normalized_phone) <= 15:

            flash(
                "Enter a valid phone number containing 7 to 15 digits.",
                "danger"
            )

        else:

            reports = PhoneReport.query.filter_by(
                phone_number=normalized_phone
            ).order_by(
                PhoneReport.created_at.desc()
            ).all()

            total_reports = len(reports)

            category_summary = db.session.query(
                PhoneReport.category,
                db.func.count(PhoneReport.id)
            ).filter_by(
                phone_number=normalized_phone
            ).group_by(
                PhoneReport.category
            ).all()

            if total_reports == 0:

                risk = "Unrated"
                risk_score = None
                risk_color = "secondary"

                risk_message = (
                    "No community reports found. This does not "
                    "prove that the number is safe."
                )

            elif total_reports <= 2:

                risk_score = total_reports * 20
                risk = "Low Community Evidence"
                risk_color = "warning"

                risk_message = (
                    "A small number of community reports exists. "
                    "Treat the number cautiously and verify independently."
                )

            elif total_reports == 3:

                risk_score = 60
                risk = "Medium Community Concern"
                risk_color = "warning"

                risk_message = (
                    "Several community reports exist. Be careful "
                    "and verify the caller before responding."
                )

            else:

                risk_score = min(
                    total_reports * 20, 100
                )

                risk = "High Community Concern"
                risk_color = "danger"

                risk_message = (
                    "Multiple community reports exist. Avoid sharing "
                    "OTPs, passwords or payment information."
                )

    return render_template(
        "phone_checker.html",
        phone=phone,
        reports=reports,
        total_reports=total_reports,
        category_summary=category_summary,
        risk=risk,
        risk_score=risk_score,
        risk_color=risk_color,
        risk_message=risk_message
    )


# SUBMIT A PHONE NUMBER SCAM REPORT

@app.route("/report-phone", methods=["POST"])
@login_required
def report_phone():

    phone = request.form.get(
        "phone", ""
    ).strip()

    category = request.form.get(
        "category", ""
    ).strip()

    description = request.form.get(
        "description", ""
    ).strip()

    allowed_categories = [
        "Scam Call",
        "Fake Bank Call",
        "OTP Fraud",
        "Job Scam",
        "Investment Scam",
        "Delivery Scam",
        "Other"
    ]

    normalized_phone = normalize_phone(phone)

    if not 7 <= len(normalized_phone) <= 15:

        flash(
            "Please enter a valid phone number.",
            "danger"
        )

        return redirect(url_for("phone_check"))

    if category not in allowed_categories:

        flash(
            "Please select a valid scam category.",
            "danger"
        )

        return redirect(url_for("phone_check"))

    if len(description) < 10:

        flash(
            "Please provide at least 10 characters describing the incident.",
            "danger"
        )

        return redirect(url_for("phone_check"))

    if len(description) > 1000:

        flash(
            "Description cannot exceed 1000 characters.",
            "danger"
        )

        return redirect(url_for("phone_check"))

    new_report = PhoneReport(
        phone_number=normalized_phone,
        category=category,
        description=description,
        user_id=current_user.id
    )

    db.session.add(new_report)
    db.session.commit()

    flash(
        "Your phone number report has been submitted successfully.",
        "success"
    )

    return redirect(url_for("phone_check"))


# GENERAL REPORT A SCAM PAGE

@app.route("/report-scam", methods=["GET", "POST"])
@login_required
def report_scam():

    if request.method == "POST":

        report_type = request.form.get(
            "report_type", ""
        ).strip()

        target = request.form.get(
            "target", ""
        ).strip()

        category = request.form.get(
            "category", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        allowed_types = [
            "Phone",
            "URL",
            "Message",
            "Email"
        ]

        if report_type not in allowed_types:

            flash(
                "Please select a valid scam type.",
                "danger"
            )

        elif not target or not category or not description:

            flash(
                "Please fill in all fields.",
                "danger"
            )

        elif len(target) > 500 or len(description) > 1000:

            flash(
                "The submitted information is too long.",
                "danger"
            )

        else:

            if report_type == "Phone":

                target = normalize_phone(target)

                if not 7 <= len(target) <= 15:

                    flash(
                        "Please enter a valid phone number.",
                        "danger"
                    )

                    return render_template("report_scam.html")

            new_report = ScamReport(
                report_type=report_type,
                target=target,
                category=category,
                description=description,
                user_id=current_user.id
            )

            db.session.add(new_report)
            db.session.commit()

            flash(
                "Your scam report was submitted successfully.",
                "success"
            )

            return redirect(url_for("my_scam_reports"))

    return render_template("report_scam.html")


# ADMIN VERIFICATION

@app.route("/admin/verification")
@login_required
def admin_verification():

    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash("Access denied. Admin permission required.", "danger")
        return redirect(url_for("dashboard"))

    reports = ScamReport.query.order_by(
        ScamReport.created_at.desc()
    ).all()

    return render_template(
        "admin_verification.html",
        reports=reports
    )


# UPDATE REPORT STATUS

@app.route(
    "/admin/verification/<int:report_id>/<action>",
    methods=["POST"]
)
@login_required
def update_report_status(report_id, action):

    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash("You are not authorized to perform this action.", "danger")
        return redirect(url_for("dashboard"))

    report = db.session.get(ScamReport, report_id)

    if report is None:
        flash("Report not found.", "danger")
        return redirect(url_for("admin_verification"))

    if action == "verify":
        report.status = "Verified"
        flash("Report verified successfully!", "success")

    elif action == "reject":
        report.status = "Rejected"
        flash("Report rejected successfully!", "success")

    else:
        flash("Invalid action.", "danger")
        return redirect(url_for("admin_verification"))

    db.session.commit()

    return redirect(url_for("admin_verification"))


# SETTINGS PAGE WITH PASSWORD CHANGE

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():

    if request.method == "POST":

        current_password = request.form.get(
            "current_password", ""
        )

        new_password = request.form.get(
            "new_password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not current_password or not new_password or not confirm_password:

            flash(
                "Please fill in all password fields.",
                "danger"
            )

            return redirect(url_for("settings"))

        if not check_password_hash(
            current_user.password,
            current_password
        ):

            flash(
                "Your current password is incorrect.",
                "danger"
            )

            return redirect(url_for("settings"))

        if len(new_password) < 8:

            flash(
                "New password must contain at least 8 characters.",
                "danger"
            )

            return redirect(url_for("settings"))

        if new_password != confirm_password:

            flash(
                "New passwords do not match.",
                "danger"
            )

            return redirect(url_for("settings"))

        if check_password_hash(
            current_user.password,
            new_password
        ):

            flash(
                "Please choose a different password.",
                "danger"
            )

            return redirect(url_for("settings"))

        current_user.password = generate_password_hash(
            new_password
        )

        db.session.commit()

        flash(
            "Your password has been changed successfully!",
            "success"
        )

        return redirect(url_for("settings"))

    return render_template("settings.html")


# MY SCAM REPORTS

@app.route("/my-scam-reports")
@login_required
def my_scam_reports():

    reports = ScamReport.query.filter_by(
        user_id=current_user.id
    ).order_by(
        ScamReport.created_at.desc()
    ).all()

    return render_template(
        "my_scam_reports.html",
        reports=reports
    )


# LOGOUT

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "You have logged out successfully.",
        "success"
    )

    return redirect(url_for("login"))


# START APPLICATION

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    print("AI Scam Detection System is starting...")
    print("Database initialized successfully.")
    print("Machine learning model loaded successfully.")

    print("\n========== REGISTERED FLASK ROUTES ==========")

    for route in app.url_map.iter_rules():
        print(route, "->", route.endpoint)

    print("==============================================")

    app.run(debug=True)
