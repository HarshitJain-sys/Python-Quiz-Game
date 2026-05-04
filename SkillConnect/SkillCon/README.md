# SkillCon 🔧

India's trusted skill marketplace — OTP verified, safe & transparent.

## Features
- Client & Professional dashboards (separate UI)
- 80+ profession categories + custom option
- OTP-verified job completion & reviews
- Aadhaar upload + Skill quiz + Work proof verification
- Unverified → Partially Verified → ✅ Verified badge system
- Gig packages (Basic / Standard / Premium)
- Distance-based proportional travel fee
- Portfolio photos for professionals
- Smooth animated client profile popup for professionals
- Built-in job messaging
- SOS safety button
- Save/favourite professionals
- Transaction history
- Cash on delivery + Online payment (Razorpay ready)

## How to run

### Step 1 — Install & Start backend
Double-click `start.bat` (Windows)

OR run manually:
```
pip install fastapi uvicorn PyJWT "bcrypt==4.0.1" python-multipart
python -m uvicorn main:app --reload --port 8000
```

### Step 2 — Open frontend
Open `index.html` in your browser (double-click it)

## Demo accounts
- **Client:** client@demo.com / demo123
- **Professional:** pro@demo.com / demo123
- **Electrician:** elec@demo.com / demo123

## OTP Flow
1. Client books job → sees **Completion OTP**
2. Client shares OTP with worker when work is done
3. Worker enters OTP → job marked complete
4. Client requests review → Worker sees **Review OTP**
5. Worker shares Review OTP via messages
6. Client enters Review OTP → submits rating & review

## Payment
Razorpay integration is ready — just replace `rzp_test_DEMO_KEY_REPLACE_ME` in main.py with your actual API key.
