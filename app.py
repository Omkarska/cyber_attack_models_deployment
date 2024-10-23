from flask import Flask, render_template, request
from sql_injection import predict_sql_injection
from xss_detection import predict_xss
from werkzeug.utils import secure_filename
from file_analysis import upload_file_to_virustotal, fetch_scan_results, summarize_results
import os

app = Flask(__name__)

API_KEY = "55a3e673e92ad483a766e04a1ff0ebd614987f8021dc4bc66f2dd68ea69fee7f"

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'pdf', 'txt', 'doc', 'docx'}

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/sql-injection', methods=['GET', 'POST'])
def sql_injection():
    prediction_result = None
    confidence_score = None
    query = ""

    if request.method == 'POST':
        query = request.form['sqlInput']
        label, confidence = predict_sql_injection(query)
        prediction_result = "SQL Injection" if label == 1 else "Not SQL Injection"
        confidence_score = round(confidence, 4)

    return render_template('sql_check.html', query=query, prediction=prediction_result, confidence=confidence_score)

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    prediction_result = None
    confidence_score = None
    query = ""

    if request.method == 'POST':
        query = request.form['xssInput']
        label, confidence = predict_xss(query)
        prediction_result = "XSS Attack" if label == 1 else "Not XSS Attack"
        confidence_score = confidence

    return render_template('xss_check.html', query=query, prediction=prediction_result, confidence=confidence_score)

@app.route('/file-analysis', methods=['GET', 'POST'])
def file_analysis():
    prediction = None
    confidence = None

    if request.method == 'POST':
        # Check if a file is provided
        if 'file' not in request.files:
            return render_template('file_analysis.html', prediction="No file selected", confidence=None)

        file = request.files['file']

        # Check if file is valid and allowed
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Upload the file to VirusTotal
            scan_id = upload_file_to_virustotal(file_path, API_KEY)

            if scan_id:
                # Fetch scan results
                scan_results = fetch_scan_results(scan_id, API_KEY)

                if scan_results:
                    # Summarize the results
                    prediction, confidence = summarize_results(scan_results)
                    confidence = round(confidence,2)
            # Optionally: delete the file after processing
            os.remove(file_path)

    return render_template('file_analysis.html', prediction=prediction, confidence=confidence)

if __name__ == '__main__':
    app.run(debug=True)
