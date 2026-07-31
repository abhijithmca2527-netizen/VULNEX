import re
import os
import random
import requests

from dotenv import load_dotenv

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse

from .models import User
from django.shortcuts import render

load_dotenv()

API_KEY = os.getenv("TWOFACTOR_API_KEY")





def send_otp(request):

    mobile = request.POST.get("mobile")

    url = f"https://2factor.in/API/V1/{API_KEY}/SMS/{mobile}/AUTOGEN2/OTP1"

    response = requests.get(url)

    data = response.json()

    if data["Status"] == "Success":

        request.session["otp_session"] = data["Details"]

    return JsonResponse(data)


def verify_otp(request):

    otp = request.POST.get("otp")

    session_id = request.session.get("otp_session")

    url = f"https://2factor.in/API/V1/{API_KEY}/SMS/VERIFY/{session_id}/{otp}"

    response = requests.get(url)

    data = response.json()

    if data["Status"] == "Success":

        request.session["otp_verified"] = True

    return JsonResponse(data)



# 1. Public Landing Page (Before Login)
def landing_view(request):
    return render(request, 'home/index.html')

# ==========================
# Login
# ==========================
def login(request):

    if request.method == "POST":

        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")

        try:
            user = User.objects.get(email=email)

            if check_password(password, user.password):

                request.session["user_id"] = user.id
                request.session["user_name"] = user.full_name

                return redirect("dashboard")

            else:
                messages.error(request, "Invalid password.")

        except User.DoesNotExist:
            messages.error(request, "Email not found.")

    return render(request, "auth/login.html")


# ==========================
# Dashboard
# ==========================
def dashboard(request):

    if "user_id" not in request.session:
        return redirect("login")

    user = User.objects.get(id=request.session["user_id"])

    return render(
        request,
        "dashboard/dashboard.html",
        {
            "user": user
        }
    )


# ==========================
# Logout
# ==========================
def logout(request):

    request.session.flush()

    return redirect("login")

















def register(request):

    if request.method == "POST":

        full_name = request.POST.get("full_name", "").strip()
        email = request.POST.get("email", "").strip().lower()
        mobile = request.POST.get("mobile_number", "").strip()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")

        # Required Fields
        if not all([full_name, email, mobile, password, confirm_password]):
            messages.error(request, "All fields are required.")
            return redirect("register")

        # Full Name Validation
        if len(full_name) < 3:
            messages.error(request, "Full name must contain at least 3 characters.")
            return redirect("register")

        if not full_name[0].isupper():
            messages.error(request, "Full name must start with a capital letter.")
            return redirect("register")

        if not re.fullmatch(r"[A-Za-z ]+", full_name):
            messages.error(request, "Full name should contain only letters and spaces.")
            return redirect("register")

        # Email Validation
        email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

        if not re.fullmatch(email_pattern, email):
            messages.error(request, "Enter a valid email address.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        # Mobile Validation
        if not re.fullmatch(r"[6-9]\d{9}", mobile):
            messages.error(request, "Enter a valid 10-digit mobile number.")
            return redirect("register")

        if User.objects.filter(mobile_number=mobile).exists():
            messages.error(request, "Mobile number already registered.")
            return redirect("register")

        # Password Validation
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if len(password) < 6:
            messages.error(request, "Password must contain at least 6 characters.")
            return redirect("register")

        if not password[0].isupper():
            messages.error(request, "Password must start with a capital letter.")
            return redirect("register")

        if not re.search(r"\d", password):
            messages.error(request, "Password must contain at least one number.")
            return redirect("register")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            messages.error(request, "Password must contain at least one special character.")
            return redirect("register")

                # OTP Validation
        if not request.session.get("otp_verified", False):
            messages.error(request, "Please verify your mobile number first.")
            return redirect("register")

        # Save User
        User.objects.create(
            full_name=full_name,
            email=email,
            mobile_number=mobile,
            password=make_password(password),
            otp_verified=True
        )

        messages.success(request, "Registration Successful.")

        request.session.pop("otp_session", None)
        request.session.pop("otp_verified", None)

        return redirect("login")
    
    return render(request, "auth/register.html")

# ==========================
# Login
# ==========================
def login(request):

    if request.method == "POST":

        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")

        try:
            user = User.objects.get(email=email)

            if check_password(password, user.password):

                request.session["user_id"] = user.id
                request.session["user_name"] = user.full_name

                return redirect("dashboard")

            else:
                messages.error(request, "Invalid password.")

        except User.DoesNotExist:
            messages.error(request, "Email not found.")

    return render(request, "auth/login.html")


# ==========================
# Dashboard
# ==========================
def dashboard(request):

    if "user_id" not in request.session:
        return redirect("login")

    user = User.objects.get(id=request.session["user_id"])

    return render(
        request,
        "dashboard/dashboard.html",
        {
            "user": user
        }
    )


# ==========================
# Logout
# ==========================
def logout(request):

    request.session.flush()

    return redirect("login")

def profile_view(request):
    """Renders the user profile page."""
    return render(request, 'profile/profile.html')