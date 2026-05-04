@echo off
echo Installing dependencies...
pip install fastapi uvicorn PyJWT "bcrypt==4.0.1" python-multipart

echo.
echo Starting SkillCon backend...
echo.
echo Once you see "Application startup complete", open index.html in your browser.
echo.
python -m uvicorn main:app --reload --port 8000
pause
