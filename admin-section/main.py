from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from flask_cors import CORS
from datetime import datetime
import re
from datetime import datetime, timedelta
import bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response
load_dotenv()

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

supabase_url = os.getenv('supabase_url')
supabase_key = os.getenv('supabase_key')

# Create Supabase client
supabase = create_client(supabase_url, supabase_key)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def verify_password(input_password, stored_hash):
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hash.encode('utf-8'))
def is_email(input_string):
    # Regular expression to match an email pattern
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", input_string))


@app.route('/authCredentials', methods=['POST'])
def authCredentials():
    data = request.get_json()
    username_or_email = data.get('username')
    password = data.get('password')

    if not username_or_email or not password:
        return jsonify({"error": "Missing username or password"}), 400
    
    # Check if input is an email or username
    if is_email(username_or_email):
        # Search by email
        response = supabase.table('users').select('password', 'email').eq('email', username_or_email).single().execute()
    else:
        # Search by username
        response = supabase.table('users').select('password', 'email').eq('username', username_or_email).single().execute()

    user_data = response.data  # Extract actual data

    if not user_data:  # Check if user exists
        return jsonify({"error": "User not found"}), 404
    
    stored_hash = user_data['password']  # Hashed password stored in the database
    
    # Verify the entered password against the stored hash
    if verify_password(password, stored_hash):
        # Generate a JWT token for the authenticated user
        access_token = create_access_token(identity=user_data['email'])  # You can use email or user ID for the identity
        return jsonify({"message": "Login successful", "access_token": access_token}), 200
    else:
        return jsonify({"error": "Invalid password"}), 400

# Protected route: Example of a protected resource
@app.route('/protected-route', methods=['GET'])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()  # This will return the user's email

    # Use the email to retrieve user-specific data from your database
    user_info = supabase.table('users').select('username', 'email').eq('email', current_user).single()
    
    if user_info is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(logged_in_as=user_info), 200

# @app.route('/api/addArticle', methods=['POST'])
# def add_article():

# @app.route('/api/modifyArticle', methods=['POST'])
# def modify_article():

# @app.route('/api/deleteArticle', methods=['GET'])
# def delete_article():

@app.route('/api/fetchArticles', methods=['GET'])
def get_data():

    response = supabase.table('cards').select().execute()
    if 'status_code' in response and response['status_code'] == 200:
        return jsonify(response['data']), 200
    else:
        return jsonify({'error': 'Failed to fetch data'}), 500

@app.route('/api/fetchEmployees', methods=['GET'])
def get_employees():
    try:
        response = supabase.table("employees").select("employeeid, name").execute()
        response_dict = response.model_dump()

        if "error" in response_dict and response_dict["error"]:
            return jsonify({"error": response_dict["error"]["message"]}), 500

        return jsonify(response_dict["data"]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/deleteEmployees', methods=['POST'])
def delete_employess():
    try:
        data = request.json
        if not isinstance(data, list):
            return jsonify({"error": "Invalid request"}), 400
        for emp in data:
            empid = emp.get('employeeid')
            response = supabase.table("employees").delete().eq("employeeid", empid).execute()
            response_dict = response.model_dump()
        if "error" in response_dict and response_dict["error"]:
                return jsonify({"error": f"Supabase error: {response_dict['error']['message']}"}), 400

        if "data" in response_dict and response_dict["data"]:
                return jsonify({"message": "employees have been deleted successfully"}), 200

        return jsonify({"message": "employees have been deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/addEmployees', methods=['POST'])
def add_employees():
    try:
        data = request.json
        if not isinstance(data, list):
            return jsonify({"error": "Invalid data format, expecting a list"}), 400

        sanitized_data = []
        for employee in data:
            sanitized_employee = {
                "name": employee.get("name"),
                "job": employee.get("job"),
                "prix": employee.get("prix"),
                "phonenumber": employee.get("phonenumber") if employee.get("phonenumber") else None,
                "date_created": datetime.utcnow().isoformat(),
            }
            sanitized_data.append(sanitized_employee)

        print(f"Sanitized employee data: {sanitized_data}")

        response = supabase.table('employees').insert(sanitized_data).execute()

        response_dict = response.model_dump()

        if "error" in response_dict and response_dict["error"]:
            raise Exception(response_dict["error"]["message"])

        return jsonify({"message": "Employees added successfully!"}), 200

    except Exception as e:

        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/fetchNewEmployees', methods=['GET'])
def fetch_new_employees():
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)

    response = supabase.table("employees") \
        .select("employeeid, name") \
        .gte("date_created", five_minutes_ago.isoformat()) \
        .execute()
    app.logger.info(f"Fetching employees created after: {five_minutes_ago.isoformat()}")


    return jsonify(response.data)

@app.route('/api/submitPointage', methods=['POST'])
def submit_Pointage():
    try:
        data = request.json
        if not isinstance(data, list) or not all(isinstance(record, dict) for record in data):
            raise ValueError("Invalid payload format. Expected a list of dictionaries.")

        formatted_data = [
            {
                "employeeid": record["EmployeeID"],
                "date": record["Date"],
                "status": record["Status"]
            }
            for record in data
        ]

        employee_dates = [(record["employeeid"], record["date"]) for record in formatted_data]

        existing_records_response = supabase.table('pointage').select('employeeid, date').in_(
            'employeeid', [str(e[0]) for e in employee_dates]
        ).in_(
            'date', [str(e[1]) for e in employee_dates]
        ).execute()

        response_dict = existing_records_response.model_dump()
        # app.logger.error(f"Existing records response: {response_dict}")

        if 'error' in response_dict and response_dict['error']:
            raise Exception(response_dict['error']['message'])

        existing_records = {(record['employeeid'], record['date']) for record in response_dict['data']}

        new_records = [record for record in formatted_data if (record["employeeid"], record["date"]) not in existing_records]
        already_stored = [record for record in formatted_data if (record["employeeid"], record["date"]) in existing_records]

        # app.logger.error(f"New records: {new_records}")
        # app.logger.error(f"Already stored records: {already_stored}")

        if new_records:
            insert_response = supabase.table('pointage').insert(new_records, upsert=True).execute()
            insert_response_dict = insert_response.model_dump()
            # app.logger.error(f"Insert response: {insert_response_dict}")

            if 'error' in insert_response_dict and insert_response_dict['error']:
                raise Exception(insert_response_dict['error']['message'])

        message = {
            "new_records": len(new_records),
            "already_stored": len(already_stored),
            "message": f"Stored {len(new_records)} new records, {len(already_stored)} already stored."
        }

        return jsonify(message), 200

    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/getSubmittedDates', methods=['GET'])
def get_submitted_dates():
    try:
        response = supabase.table('submitted_dates').select('*').execute()

        response_dict = response.model_dump()

        if 'error' in response_dict and response_dict['error']:
            raise Exception(response_dict['error']['message'])
        
        distinct_dates = [row['date'] for row in response_dict['data']]

        return jsonify(distinct_dates)

    except Exception as e:
        app.logger.error(f"Error fetching submitted dates: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/updatePointage', methods=['POST'])
def update_pointage():
    try:
        data = request.get_json()
        # app.logger.info(f"Received payload: {data}")

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list) or not all(isinstance(record, dict) for record in data):
            return jsonify({"error": "Invalid data format. Expected a list of dictionaries"}), 400

        for record in data:
            employeeid = record.get("EmployeeID")
            date = record.get("Date")
            status = record.get("Status")

            if not employeeid or not date or status is None:
                return jsonify({"error": f"Missing fields for employeeid {employeeid}"}), 400

            try:
                status = int(status)
            except ValueError:
                return jsonify({"error": f"Invalid status value for employeeid {employeeid}"}), 400

            update_payload = {"status": status}

            response = (
                supabase.table("pointage")
                .update(update_payload)
                .eq("employeeid", employeeid)
                .eq("date", date)
                .execute()
            )

            response_dict = response.model_dump()  

        if "error" in response_dict and response_dict["error"]:
                app.logger.error(f"Supabase error: {response_dict['error']['message']}")
                return jsonify({"error": f"Supabase error: {response_dict['error']['message']}"}), 400

        if "data" in response_dict and response_dict["data"]:
                return jsonify({"message": "Attendance record updated successfully"}), 200

        return jsonify({"message": "Successfully processed all records"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/api/addAdvances', methods=['POST'])
def add_Advances():
    try:
        data = request.json
        if not isinstance(data, list) or not all(isinstance(record, dict) for record in data):
            raise ValueError("Invalid payload format. Expected a list of dictionaries.")

        advances_dict = [
            {
                "employeeid": record["EmployeeID"],
                "amount": record["Amount"],
                "date": record["Date"]
            }
            for record in data
        ]

        response = supabase.table('advance').insert(advances_dict).execute()
        response_dict = response.model_dump()

        if 'error' in response_dict and response_dict['error']:
            raise Exception(response_dict['error']['message'])

        return jsonify({"message": "Advances added successfully!"}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/fetchSalaries', methods=['GET'])
def fetch_salaries():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        employee_ids = request.args.get('employee_ids')  # Get employee IDs from request

        if not start_date or not end_date:
            return jsonify({"error": "Start date and end date are required."}), 400

        # Convert comma-separated employee IDs into a list
        if employee_ids:
            employee_ids = employee_ids.split(",")
        
        # Fetch attendance records
        attendance_query = supabase.table('pointage') \
            .select("employeeid, date, status") \
            .gte('date', start_date) \
            .lte('date', end_date)

        if employee_ids:
            attendance_query = attendance_query.in_("employeeid", employee_ids)  # Filter by selected employees

        attendance_response = attendance_query.execute()
        attendance_response_dict = attendance_response.model_dump()

        if 'error' in attendance_response_dict and attendance_response_dict['error']:
            raise Exception(attendance_response_dict['error']['message'])

        attendance_data = attendance_response_dict['data']

        # Fetch employee details
        employees_query = supabase.table('employees') \
            .select("employeeid, name, job, prix")

        if employee_ids:
            employees_query = employees_query.in_("employeeid", employee_ids)

        employees_response = employees_query.execute()
        employees_response_dict = employees_response.model_dump()

        if 'error' in employees_response_dict and employees_response_dict['error']:
            raise Exception(employees_response_dict['error']['message'])

        employees_data = {e['employeeid']: e for e in employees_response_dict['data']}

        # Fetch advances
        advances_query = supabase.table('advance') \
            .select("employeeid, amount") \
            .gte('date', start_date) \
            .lte('date', end_date)

        if employee_ids:
            advances_query = advances_query.in_("employeeid", employee_ids)

        advances_response = advances_query.execute()
        advances_response_dict = advances_response.model_dump()

        if 'error' in advances_response_dict and advances_response_dict['error']:
            raise Exception(advances_response_dict['error']['message'])

        advances_data = advances_response_dict['data']

        employee_salaries = {}

        for record in attendance_data:
            emp_id = record["employeeid"]
            if emp_id not in employee_salaries:
                employee_salaries[emp_id] = {
                    "employeeid": emp_id,
                    "name": employees_data[emp_id]["name"],
                    "job": employees_data[emp_id]["job"],
                    "prix": employees_data[emp_id]["prix"],
                    "total_days_present": 0,
                    "total_days_absent": 0,
                    "total_salary": 0,
                    "total_advances": 0,
                    "final_salary": 0,
                }

            if record["status"] == 1:
                employee_salaries[emp_id]["total_days_present"] += 1
            else:
                employee_salaries[emp_id]["total_days_absent"] += 1

        for emp_id, details in employee_salaries.items():
            daily_rate = details["prix"]
            details["total_salary"] = details["total_days_present"] * daily_rate

        for advance in advances_data:
            emp_id = advance["employeeid"]
            if emp_id in employee_salaries:
                employee_salaries[emp_id]["total_advances"] += advance["amount"]

        for emp_id, details in employee_salaries.items():
            details["final_salary"] = details["total_salary"] - details["total_advances"]

        return jsonify(list(employee_salaries.values())), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
if __name__ == '__main__':
    app.run(debug=True)
