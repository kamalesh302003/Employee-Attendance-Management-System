#import packages 
from fastapi import FastAPI,Request,Form,Response
from fastapi.responses import HTMLResponse,RedirectResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import datetime,date,timedelta
import sqlite3,json,base64,hashlib,hmac,secrets,os,io

app=FastAPI()
app.mount("/static",StaticFiles(directory="static"),name="static")
templates=Jinja2Templates(directory="templates")
SECRET_KEY=os.getenv("JWT_SECRET_KEY","supersecretkey123")
ACCESS_TOKEN_EXPIRE_SECONDS=3600
DB_PATH="attendance.db"

def get_db_connection():
    conn=sqlite3.connect(DB_PATH,check_same_thread=False)
    conn.row_factory=sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        cursor=conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'employee'
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER,
            date TEXT,
            checkin TEXT,
            checkout TEXT
        )
        """)
        conn.commit()
        cursor.execute("PRAGMA table_info(employees)")
        columns=[row[1] for row in cursor.fetchall()]
        if "role" not in columns:
            cursor.execute("ALTER TABLE employees ADD COLUMN role TEXT DEFAULT 'employee'")
            conn.commit()
        cursor.execute("SELECT * FROM employees WHERE role='admin' LIMIT 1")
        if cursor.fetchone() is None:
            password="302003"
            salt=secrets.token_bytes(16)
            digest=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,100_000)
            admin_hash=base64.urlsafe_b64encode(salt).decode()+"$"+base64.urlsafe_b64encode(digest).decode()
            cursor.execute(
                "INSERT OR IGNORE INTO employees(username,password,role) VALUES(?,?,?)",
                ("Kamalesh Chandrasekaran",admin_hash,"admin"),
            )
            conn.commit()

init_db()

def hash_password(password:str)->str:
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,100_000)
    return base64.urlsafe_b64encode(salt).decode()+"$"+base64.urlsafe_b64encode(digest).decode()

def verify_password(password:str,stored:str)->bool:
    if "$" not in stored:
        return False
    salt_b64,digest_b64=stored.split("$",1)
    salt=base64.urlsafe_b64decode(salt_b64.encode())
    expected=base64.urlsafe_b64decode(digest_b64.encode())
    actual=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,100_000)
    return hmac.compare_digest(actual,expected)

def jwt_encode(payload:dict)->str:
    def _b64(data:dict)->str:
        return base64.urlsafe_b64encode(json.dumps(data,separators=(",",":")).encode()).rstrip(b"=").decode()
    header={"alg":"HS256","typ":"JWT"}
    header_b64=_b64(header)
    payload_b64=_b64(payload)
    signature=hmac.new(SECRET_KEY.encode(),f"{header_b64}.{payload_b64}".encode(),hashlib.sha256).digest()
    signature_b64=base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def jwt_decode(token:str):
    try:
        header_b64,payload_b64,signature_b64=token.split(".")
        expected_signature=base64.urlsafe_b64encode(
            hmac.new(SECRET_KEY.encode(),f"{header_b64}.{payload_b64}".encode(),hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(signature_b64,expected_signature):
            return None
        padded_payload=payload_b64 + "=" *(-len(payload_b64) % 4)
        payload=json.loads(base64.urlsafe_b64decode(padded_payload))
        if payload.get("exp") and payload["exp"] < int(datetime.utcnow().timestamp()):
            return None
        return payload
    except Exception:
        return None

def create_access_token(user_id:int,username:str,role:str)->str:
    exp=int((datetime.utcnow()+timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)).timestamp())
    return jwt_encode({"user_id":user_id,"username":username,"role":role,"exp":exp})

def get_current_user(request:Request):
    token=request.cookies.get("token")
    if not token:
        return None
    return jwt_decode(token)

def get_user_by_username(username:str):
    with get_db_connection() as conn:
        cursor=conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE username=?", (username,))
        return cursor.fetchone()

def register_employee(username:str,password:str,role:str="employee"):
    if not username or not password:
        return False,"Username and password are required."
    username=username.strip()
    if get_user_by_username(username):
        return False,f"Username '{username}' already exists."
    hashed=hash_password(password)
    try:
        with get_db_connection() as conn:
            cursor=conn.cursor()
            cursor.execute(
                "INSERT INTO employees(username,password,role) VALUES(?,?,?)",
                (username,hashed,role or "employee"),
            )
            conn.commit()
        return True,f"Added employee '{username}'."
    except sqlite3.IntegrityError:
        return False,f"Username '{username}' already exists."
    except Exception as exc:
        return False,f"Could not add '{username}':{exc}"

def authenticate_user(username:str,password:str):
    user=get_user_by_username(username)
    if not user:
        return None
    stored=user["password"]
    if "$" in stored:
        return user if verify_password(password,stored) else None
    if password==stored:
        hashed=hash_password(password)
        with get_db_connection() as conn:
            cursor=conn.cursor()
            cursor.execute("UPDATE employees SET password=? WHERE id=?",(hashed, user["id"]))
            conn.commit()
        return get_user_by_username(username)
    return None

def compute_duration(checkin:str,checkout:str)->str:
    if not checkin or not checkout:
        return ""
    try:
        fmt="%H:%M:%S"
        in_time=datetime.strptime(checkin,fmt)
        out_time=datetime.strptime(checkout,fmt)
        diff=out_time-in_time
        if diff.days<0:
            return ""
        hours=diff.seconds//3600
        minutes=(diff.seconds%3600)//60
        return f"{hours}h {minutes}m"
    except Exception:
        return ""

def build_pdf(lines):
    def escape(value:str)->str:
        return value.replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
    stream_parts=[]
    y=760
    for line in lines:
        stream_parts.append(f"BT /F1 12 Tf 50 {y} Td ({escape(line)}) Tj ET")
        y-=16
    stream_data="\n".join(stream_parts).encode("latin-1")
    length=len(stream_data)

    objects=[
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
        f"4 0 obj\n<< /Length {length} >>\nstream\n".encode("latin-1") + stream_data + b"\nendstream\nendobj\n",
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    pdf=b"%PDF-1.4\n"
    xref=[0]
    for obj in objects:
        xref.append(len(pdf))
        pdf+=obj
    xref_offset=len(pdf)
    pdf+=f"xref\n0 {len(objects)+1}\n0000000000 65535 f\n".encode("latin-1")
    for offset in xref[1:]:
        pdf+=f"{offset:010d} 00000 n\n".encode("latin-1")
    pdf+=f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1")
    return pdf

@app.get("/home")
def home():
    return {"message":"Welcome to Employee Attendance System"}

@app.get("/",response_class=HTMLResponse)
def login_page(request:Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error":None}
    )

@app.post("/login")
def login(request:Request,username:str=Form(...),password:str=Form(...)):
    user=authenticate_user(username,password)
    if not user:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error":"Invalid username or password."}
        )
    token=create_access_token(user["id"],user["username"],user["role"])
    response=RedirectResponse("/dashboard",status_code=303)
    response.set_cookie("token",token,httponly=True,max_age=ACCESS_TOKEN_EXPIRE_SECONDS)
    return response

@app.get("/logout")
def logout():
    response=RedirectResponse("/",status_code=303)
    response.delete_cookie("token")
    return response

@app.get("/dashboard",response_class=HTMLResponse)
def dashboard(request:Request):
    user=get_current_user(request)
    if not user:
        return RedirectResponse("/",status_code=303)
    with get_db_connection() as conn:
        cursor=conn.cursor()
        if user["role"]=="admin":
            employees=cursor.execute(
                "SELECT id,username,role FROM employees ORDER BY username"
            ).fetchall()
            attendance_count=cursor.execute(
                "SELECT COUNT(*) FROM attendance"
            ).fetchone()[0]
            summary=cursor.execute(
                """
                SELECT COUNT(*) AS total,
                SUM(CASE WHEN checkout IS NOT NULL THEN 1 ELSE 0 END) AS completed
                FROM attendance
                """
            ).fetchone()
            recent_rows=cursor.execute(
                """
                SELECT a.date,a.checkin,a.checkout,e.username
                FROM attendance a
                JOIN employees e
                ON e.id=a.employee_id
                ORDER BY a.date DESC
                LIMIT 10
                """
            ).fetchall()
            recent=[
                {
                    "date":row["date"],
                    "username":row["username"],
                    "checkin":row["checkin"],
                    "checkout":row["checkout"],
                    "hours":compute_duration(
                        row["checkin"],
                        row["checkout"]
                    ),
                }
                for row in recent_rows
            ]
            return templates.TemplateResponse(
                request=request,
                name="admin_dashboard.html",
                context={
                    "user":user,
                    "employees":employees,
                    "attendance_count":attendance_count,
                    "summary":summary,
                    "recent":recent,
                }
            )
        today=date.today().isoformat()
        record=cursor.execute(
            """
            SELECT *
            FROM attendance
            WHERE employee_id=? AND date=?
            """,
            (user["user_id"],today),
        ).fetchone()
        summary=cursor.execute(
            """
            SELECT COUNT(*) AS total,
            SUM(CASE WHEN checkout IS NOT NULL THEN 1 ELSE 0 END) AS completed
            FROM attendance
            WHERE employee_id=?
            """,
            (user["user_id"],),
        ).fetchone()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":user,
            "today_record":record,
            "summary":summary,
        }
    )

@app.post("/admin/add_employees")
def add_employee(
    request: Request,
    username:str=Form(...),
    password:str=Form(...),
    role:str=Form("employee")
):
    user=get_current_user(request)
    if not user or user["role"]!="admin":
        return {"error":"Access denied"}
    with get_db_connection() as conn:
        cursor=conn.cursor()
        existing=cursor.execute(
            "SELECT * FROM employees WHERE username=?",
            (username,)
        ).fetchone()
        if existing:
            return {"error":"Username already exists"}
        hashed_password=hash_password(password)
        cursor.execute(
            """
            INSERT INTO employees
            (username,password,role)
            VALUES(?,?,?)
            """,
            (username, hashed_password,role)
        )
        conn.commit()
    return {
        "message":"Employee added successfully",
        "username":username,
        "role":role
    }

@app.get("/admin",response_class=HTMLResponse)
def admin_page(request:Request):
    user=get_current_user(request)
    if not user or user["role"]!="admin":
        return RedirectResponse("/",status_code=303)
    return dashboard(request)

@app.post("/checkin")
def checkin(request:Request):
    user=get_current_user(request)
    if not user:
        return RedirectResponse("/",status_code=303)
    today=date.today().isoformat()
    now=datetime.now().strftime("%H:%M:%S")
    with get_db_connection() as conn:
        cursor=conn.cursor()
        existing=cursor.execute(
            "SELECT * FROM attendance WHERE employee_id=? AND date=?",
            (user["user_id"],today),
        ).fetchone()
        if existing:
            if not existing["checkin"]:
                cursor.execute(
                    "UPDATE attendance SET checkin=? WHERE id=?",
                    (now,existing["id"]),
                )
        else:
            cursor.execute(
                "INSERT INTO attendance (employee_id, date, checkin) VALUES (?,?,?)",
                (user["user_id"],today,now),
            )
        conn.commit()
    return RedirectResponse("/history",status_code=303)

@app.post("/checkout")
def checkout(request:Request):
    user=get_current_user(request)
    if not user:
        return RedirectResponse("/",status_code=303)
    today=date.today().isoformat()
    now=datetime.now().strftime("%H:%M:%S")
    with get_db_connection() as conn:
        cursor=conn.cursor()
        cursor.execute(
            "UPDATE attendance SET checkout=? WHERE employee_id=? AND date=? AND checkin IS NOT NULL",
            (now,user["user_id"],today),
        )
        conn.commit()
    return RedirectResponse("/history",status_code=303)

@app.get("/history",response_class=HTMLResponse)
def history(request:Request):
    user=get_current_user(request)
    if not user:
        return RedirectResponse("/",status_code=303)
    with get_db_connection() as conn:
        cursor=conn.cursor()
        if user["role"]=="admin":
            rows=cursor.execute(
                """
                SELECT a.date, a.checkin, a.checkout, e.username
                FROM attendance a
                JOIN employees e ON e.id=a.employee_id
                ORDER BY a.date DESC
                """
            ).fetchall()
            records=[
                {
                    "employee":row["username"],
                    "date":row["date"],
                    "checkin":row["checkin"],
                    "checkout":row["checkout"],
                    "hours":compute_duration(row["checkin"],row["checkout"]),
                }
                for row in rows
            ]
        else:
            rows=cursor.execute(
                "SELECT date,checkin,checkout FROM attendance WHERE employee_id=? ORDER BY date DESC",
                (user["user_id"],),
            ).fetchall()
            records=[
                {
                    "date":row["date"],
                    "checkin":row["checkin"],
                    "checkout":row["checkout"],
                    "hours":compute_duration(row["checkin"],row["checkout"]),
                }
                for row in rows
            ]
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={"user":user,"records":records}
    )

@app.get("/export/excel")
def export_excel(request:Request):
    user=get_current_user(request)
    if not user:
        return RedirectResponse("/",status_code=303)
    with get_db_connection() as conn:
        cursor=conn.cursor()
        if user["role"]=="admin":
            rows=cursor.execute(
                """
                SELECT a.date,a.checkin,a.checkout,e.username
                FROM attendance a
                JOIN employees e ON e.id=a.employee_id
                ORDER BY a.date DESC
                """
            ).fetchall()
            records=[
                {
                    "Employee":row["username"],
                    "Date":row["date"],
                    "Check In":row["checkin"],
                    "Check Out":row["checkout"],
                    "Hours":compute_duration(row["checkin"],row["checkout"]),
                }
                for row in rows
            ]
        else:
            rows=cursor.execute(
                "SELECT date,checkin,checkout FROM attendance WHERE employee_id=? ORDER BY date DESC",
                (user["user_id"],),
            ).fetchall()
            records=[
                {
                    "Date":row["date"],
                    "Check In":row["checkin"],
                    "Check Out":row["checkout"],
                    "Hours":compute_duration(row["checkin"],row["checkout"]),
                }
                for row in rows
            ]
    if records:
        headers=list(records[0].keys())
    else:
        headers=["Date","Check In","Check Out","Hours"]
    html_rows=["<tr>"+"".join(f"<th>{col}</th>" for col in headers)+"</tr>"]
    for record in records:
        html_rows.append(
            "<tr>"+"".join(f"<td>{record.get(col,'')}</td>" for col in headers)+"</tr>"
        )
    content=f"<table>{''.join(html_rows)}</table>"
    return Response(
        content=content,
        media_type="application/vnd.ms-excel",
        headers={"Content-Disposition":"attachment;filename=attendance_report.xls"},
    )

@app.get("/export/pdf")
def export_pdf(request:Request):
    user=get_current_user(request)
    if not user:
        return RedirectResponse("/",status_code=303)
    with get_db_connection() as conn:
        cursor=conn.cursor()
        if user["role"]=="admin":
            rows=cursor.execute(
                """
                SELECT a.date,a.checkin,a.checkout,e.username
                FROM attendance a
                JOIN employees e ON e.id=a.employee_id
                ORDER BY a.date DESC
                """
            ).fetchall()
            title="Attendance Report - All Employees"
            lines=[title,""]+[
                f"{row['username']} | {row['date']} | {row['checkin'] or '-'} | {row['checkout'] or '-'} | {compute_duration(row['checkin'],row['checkout'])}"
                for row in rows
            ]
        else:
            rows=cursor.execute(
                "SELECT date,checkin,checkout FROM attendance WHERE employee_id=? ORDER BY date DESC",
                (user["user_id"],),
            ).fetchall()
            title=f"Attendance Report-{user['username']}"
            lines=[title,""]+[
                f"{row['date']} | {row['checkin'] or '-'} | {row['checkout'] or '-'} | {compute_duration(row['checkin'], row['checkout'])}"
                for row in rows
            ]
    pdf_content=build_pdf(lines)
    return StreamingResponse(
        io.BytesIO(pdf_content),
        media_type="application/pdf",
        headers={"Content-Disposition":"attachment;filename=attendance_report.pdf"},
    )