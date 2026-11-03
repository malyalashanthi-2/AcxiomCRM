# AcxiomCRM – Flask + Python starter implementation

This is a runnable Python/Flask implementation of the AcxiomCRM assignment brief. It includes:
- Login, registration, logout, password hashing and temporary lockout after 5 failed attempts
- Admin, Manager and SalesExecutive roles with server-side route protection and sales-user record scoping
- Dashboard KPI cards and Chart.js lead/opportunity charts
- CRUD screens for Customers, Leads, Opportunities, Follow-ups and Activities
- Client-side HTML validation and server-side validation for important business rules
- Audit events for authentication and CRM create/update/delete and role changes
- JSON REST endpoints for Customers, Leads and Opportunities
- SQLite database created automatically on first run

## Requirements
Python 3.10 or newer recommended.

## Windows setup
1. Extract the ZIP.
2. Open Command Prompt in the extracted `AcxiomCRM_Flask` folder.
3. Create a virtual environment:

   `py -m venv .venv`

4. Activate it:

   `.venv\Scripts\activate`

5. Install dependencies:

   `python -m pip install -r requirements.txt`

6. Start the website:

   `python app.py`

7. Open `http://127.0.0.1:5000`

## Demo administrator
- Email: `admin@acxiomcrm.local`
- Password: `Admin@12345`

Change this password before any real deployment. New self-registered accounts receive the SalesExecutive role. An Admin can change roles from User Management.

## API examples
After logging in through the browser, the session cookie authenticates API calls:
- `GET /api/customers`
- `POST /api/customers` JSON body: `{"name":"Test Customer","email":"test@example.com","phone":"9876543210","company":"ABC"}`
- `GET /api/leads`
- `POST /api/leads` JSON body: `{"name":"New Lead","status":"New","source":"Website"}`
- `GET /api/opportunities`
- `POST /api/opportunities` JSON body: `{"name":"CRM Deal","amount":50000,"probability":50,"expected_close_date":"2027-01-15"}`

## Notes and limitations
- This is a fast-start educational implementation using Flask and SQLite, not the exact stack specified in the supplied Acxiom document. The document explicitly names ASP.NET Core Identity and Entity Framework Core; this version uses Flask-Login, Werkzeug password hashing and SQLAlchemy instead.
- The app is intended for local demonstration. Before deployment, set a strong `SECRET_KEY`, use HTTPS, configure a production database/server, disable Flask debug mode, and review access-control policy.
- Managers see team CRM data. Sales Executives see records assigned to themselves. Admins can manage all records and user roles.
- The app provides an initial functional baseline. Some enterprise-level items in the specification (for example complete report exports, advanced ownership transfer, configurable password policy, full activity history diffs, pagination, and API token authentication) are not implemented in this starter.
