Final Project IAS hn3 

------------------------------------------------------------

Final Project: Advanced Code Breaker Security System

Objective

Design and develop a secure login and access control system that demonstrates real-world cybersecurity practices, including authentication, authorization, and basic protection against attacks.

Project Overview

Create a website or system application that simulates a secure access control system. Your system must implement multiple layers of security, not just basic login.

You may use:

 Python (CLI or GUI)
 JavaScript (Web App)
 HTML/CSS/JS
 Any other approved programming language
 Required System Structure (4 Forms / Pages)

Your system must include:

1. Login Form
2. User Dashboard
3. Admin Dashboard
4. Main/Home Page




Core Security Features (REQUIRED TASKS)

 Task 1: Secure Password Authentication

 Ask for username and password
 Password must NOT be stored in plain text (simulate hashing if possible)
 Validate credentials using logic (if/else)
 Enforce strong password rules:
 Minimum 8 characters
 Must include uppercase, lowercase, number

 Task 2: Security Question Verification

 After correct login, require a second authentication layer
 Example:
 “What is your favorite color?”
   “What is your pet’s name?”
 Randomize question OR allow user-defined security question

 Task 3: Limited Attempts + Lockout System

 Maximum of 3 login attempts
 After 3 failed attempts:
 Lock account OR system
 Add cooldown timer (30 seconds before retry)
 Display warning messages




 Task 4: Role-Based Access Control (RBAC)
 Create at least 2 roles:

   Admin
   User

✔Admin Access:

 View all users
 Add/Delete users
 View login attempts/logs

✔User Access:

 Limited features only (e.g., view profile)
 Prevent users from accessing admin pages manually
NEW ADVANCED SECURITY FEATURES (REQUIRED)

Task 5: Input Validation & Error Handling

 Prevent invalid inputs (empty fields, wrong formats)
 Display user-friendly error messages

Task 6: Session Management

 Once logged in:

   Maintain a session (user stays logged in)
 Add Logout button
 Prevent access to pages after logout

Task 7: Activity Logging

 Record:
   Login attempts (success/failed)
   Time/date
   Username
Display logs in Admin Dashboard
Task 8: Basic Data Protection
 Do NOT expose passwords in code output
 Hide sensitive data in UI


Final Output Requirements
1. Working System
 Functional program or website
 Must demonstrate all required features
2. Code Submission
 Clean, organized, and commented code
3. Video Presentation (5–10 minutes)
Explain:
1. How your system works
2. Security features implemented
3. How access control is enforced
4. Challenges encountered
5. Why your system is secure








Grading Criteria 

Criteria          Percentage 
Functionality         30%        
Security Features 30%        
Code Quality       15%        
 UI/UX Design      10%        
 Presentation      15%        



BONUS FEATURES (Optional but HIGHLY ENCOURAGED)
OTP (One-Time Password simulation)
Email verification simulation
 CAPTCHA (simple math question)
Account recovery system
Database integration ( MySQL)
Password reset feature
