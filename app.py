from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, user_login_required, collector_login_required
from datetime import datetime

app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///Recycle.db")

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("email"):
            return apology("must provide email", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = :email",
                          email=request.form.get("email"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # remember user type
        session["user_type"] = "user"

        # Redirect user to home page
        return redirect("/profile")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route('/logout')
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not (email := request.form.get("email")):
            return apology("MISSING USERNAME")

        if not (password := request.form.get("password")):
            return apology("MISSING PASSWORD")

        if not (confirmation := request.form.get("confirmation")):
            return apology("PASSWORD DON'T MATCH")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = ?;", email)

        # Ensure username not in database
        if len(rows) != 0:
            return apology(f"The user '{email}' already exists. Please choose another email.")

        # Ensure first password and second password are matched
        if password != confirmation:
            return apology("password not matched")

        # Insert all into database
        id = db.execute("INSERT INTO users (email, hash, name, phone_number) VALUES (?, ?, ?, ?);",
                        email, generate_password_hash(password), request.form.get("name"), request.form.get("phone_number"))

        # Remember which user has logged in
        session["user_id"] = id

        # remember user type
        session["user_type"] = "user"

        flash("Registered!")

        return redirect("/profile")
    else:
        return render_template("register.html")


@app.route("/collector/login", methods=["GET", "POST"])
def collector_login():
    """Log collector in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("email"):
            return apology("must provide email", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM collectors WHERE email = :email",
                          email=request.form.get("email"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["collector_id"] = rows[0]["id"]

        # remember user type    
        session["user_type"] = "collector"

        # Redirect user to home page
        return redirect("/collector/profile")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("collector_login.html")
    


@app.route("/collector/register", methods=["GET", "POST"])
def collector_register():
    """Register collector"""
    if request.method == "POST":

        if not (email := request.form.get("email")):
            return apology("MISSING USERNAME")

        if not (password := request.form.get("password")):
            return apology("MISSING PASSWORD")

        if not (confirmation := request.form.get("confirmation")):
            return apology("PASSWORD DON'T MATCH")

        # Query database for username
        rows = db.execute("SELECT * FROM collectors WHERE email = ?;", email)

        # Ensure username not in database
        if len(rows) != 0:
            return apology(f"The user '{email}' already exists. Please choose another email.")

        # Ensure first password and second password are matched
        if password != confirmation:
            return apology("password not matched")

        # Insert all into database
        id = db.execute("INSERT INTO collectors (email, hash, name, phone_number, address, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?);",
                        email, generate_password_hash(password), request.form.get("name"), request.form.get("phone_number"),
                        request.form.get("address"), float(request.form.get("latitude")), float(request.form.get("longitude")))
        
        # Remember which user has logged in
        session["collector_id"] = id

        # remember user type
        session["user_type"] = "collector"

        flash("Registered!")

        return redirect("/collector/profile")
    else:
        return render_template("collector_register.html")
    

@app.route("/profile", methods=["GET", "POST"])
@user_login_required
def profile():
    """Show user profile"""
    if request.method == "GET":
        # get user info
        user = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])[0]

        # get the current tasks that user has
        current_tasks = db.execute("SELECT * FROM tasks JOIN current_tasks ON tasks.id = current_tasks.task_id WHERE current_tasks.user_id = ?;", session["user_id"])

        # get the completed tasks that user has
        completed_tasks = db.execute("SELECT * FROM tasks JOIN task_completions ON tasks.id = task_completions.task_id WHERE task_completions.user_id = ?;", session["user_id"])

        # render the profile page
        return render_template("profile.html", volunteer=user, current_tasks=current_tasks, completed_tasks=completed_tasks)
    else:
        return redirect("/profile")
    

@app.route("/tasks", methods=["GET", "POST"])
@user_login_required
def tasks():
    """Show tasks"""
    if request.method == "GET":
        # get all tasks
        tasks = db.execute("SELECT * FROM tasks;")

        # render the tasks page
        return render_template("tasks.html", tasks=tasks)
    else:
        return redirect("/tasks")
    

@app.route("/tasks/<int:task_id>", methods=["GET", "POST"])
@user_login_required
def task(task_id):
    """Show task"""
    if request.method == "GET":
        # get task
        task = db.execute("SELECT * FROM tasks WHERE id = ?;", task_id)
        print(task)
        task = task[0]

        # check if the task is already added to current tasks of the user
        ids = db.execute("SELECT * FROM current_tasks WHERE user_id = ? AND task_id = ?;", session["user_id"], task_id)
        print(ids)
        if ids:
            is_not_added = False
        else:
            is_not_added = True
            
        # render the task page
        return render_template("task.html", task=task, is_not_added=is_not_added)
    else:
        # add the task to current tasks of the user if it is not already in
        if not db.execute("SELECT * FROM current_tasks WHERE user_id = ? AND task_id = ?;", session["user_id"], task_id):
            db.execute("INSERT INTO current_tasks (user_id, task_id) VALUES (?, ?);", session["user_id"], task_id)
        
        flash("Task added!")

        return redirect("/tasks")
    

@app.route("/tasks/<int:task_id>/completed", methods=["POST"])
@user_login_required
def complete_task(task_id):
    """Complete task"""
    # add the task to completed tasks of the user
    db.execute("INSERT INTO task_completions (user_id, task_id, completion_date) VALUES (?, ?, ?);", session["user_id"], task_id, datetime.now())
    db.execute("DELETE FROM current_tasks WHERE user_id = ? AND task_id = ?;", session["user_id"], task_id)

    # increase the points of the user
    db.execute("UPDATE users SET points = points + ? WHERE id = ?;", db.execute("SELECT points FROM tasks WHERE id = ?;", task_id)[0]["points"], session["user_id"])
    
    return redirect("/profile")    

    
@app.route("/redeem", methods=["GET", "POST"])
@user_login_required
def redeem():
    return render_template("redeem.html")


@app.route("/collector/profile", methods=["GET", "POST"])
@collector_login_required
def collector_profile():
    """Show collector profile"""
    if request.method == "GET":
        # get user info
        collector = db.execute("SELECT * FROM collectors WHERE id = ?;", session["collector_id"])[0]

        # get the current tasks that collector has
        current_tasks = db.execute("SELECT * FROM tasks WHERE collector_id = ?;", session["collector_id"])

        # render the profile page
        return render_template("collector_profile.html", collector=collector, current_tasks=current_tasks)
    else:
        return redirect("/collector/profile")


@app.route("/collector/tasks/<int:task_id>", methods=["GET", "POST"])
@collector_login_required
def collector_task(task_id):
    """Show task"""
    if request.method == "GET":
        # get task
        task = db.execute("SELECT * FROM tasks WHERE id = ?;", task_id)[0]

        # render the task page
        return render_template("collector_task.html", task=task)
    else:
        return redirect("/collector/profile")
    

@app.route("/collector/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@collector_login_required
def collector_task_edit(task_id):
    """Edit task"""
    if request.method == "POST":
        # update the task
        db.execute("UPDATE tasks SET name = ?, description = ?, points = ? where id = ?;", request.form.get("name"), request.form.get("description"), request.form.get("points"), task_id)

        return redirect("/collector/profile")
    else:
        # get task
        task = db.execute("SELECT * FROM tasks WHERE id = ?;", task_id)[0]

        # render the task page
        return render_template("collector_task_edit.html", task=task)


@app.route("/collector/tasks/add", methods=["GET", "POST"])
@collector_login_required
def collector_task_add():
    """Add task"""
    if request.method == "POST":
        # add the task
        db.execute("INSERT INTO tasks (name, description, points, collector_id) VALUES (?, ?, ?, ?);", request.form.get("name"), request.form.get("description"), int(request.form.get("points")), session["collector_id"])

        return redirect("/collector/profile")
    else:
        # render the task page
        return render_template("collector_task_add.html")
    

if __name__ == '__main__':
    app.run(debug=True)