from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd, if_already_exists, owns_stock

# Configure application
app = Flask(__name__)
app.secret_key = "bhabak43!"

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

#Global Variables
registration_success = False

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    session["selected_symbol"] = None


    buyer_id = int(session["user_id"])
    user_stocks = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = ?", buyer_id)
    length = len(user_stocks)
    prev_price = []
    price = []
    total_price = []
    cash = float(db.execute("SELECT cash FROM users WHERE id = ?", buyer_id)[0]["cash"])
    grand_total = cash
    alert_message = None
    alert_type = None

    if (length != 0):
        for i in range(length):
            prev_price.append(float(db.execute("SELECT price FROM histroy WHERE buyer_id = ? AND stock_name = ? AND action = 'buy' ORDER BY (trans_id) DESC LIMIT 1", buyer_id, user_stocks[i]["symbol"])[0]["price"]))

            quote_data = lookup(user_stocks[i]["symbol"])
            shares = int(user_stocks[i]["shares"])
            price.append(float(quote_data["price"]))
            total_price.append(shares * float(quote_data["price"]))
            grand_total += shares * float(quote_data["price"])

    if session["show_alert"]:
        alert_message = session["alert_message"]
        alert_type = session["alert_type"]
        session["show_alert"] = False
    else:
        session["alert_message"] = None
        session["alert_type"] = None

    return render_template("index.html", length=length, user_stocks=user_stocks, price=price, total_price=total_price, grand_total=grand_total, cash=cash, user_name=db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"], balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"], alert_message=alert_message, alert_type=alert_type, prev_price=prev_price)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html", user_name=db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"], balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"], selected_symbol=session.get("selected_symbol"))
    else:
        stock_name = request.form.get("symbol")
        shares = int(request.form.get("stock_no"))
        quote_data = lookup(stock_name)

        if (not quote_data):
            return apology("invalid symbol", 403, "/buy")
        elif(int(shares) <= 0):
            return apology("invalid shares No.", 403, "/buy")
        else:
            price = float(quote_data["price"])
            buyer_id = int(session["user_id"])
            cash_result = db.execute("SELECT cash FROM users WHERE id = ?", buyer_id)
            cash = float(cash_result[0]["cash"])
            time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            if (cash < (price * shares)):
                return apology(f"Oops! you don't have enough money to buy {shares} shares", 403, "/buy")
            else:
                #Attempting for Transaction
                try:
                    db.execute("BEGIN")
                    
                    if owns_stock(buyer_id, stock_name):
                        db.execute("UPDATE stocks SET shares = shares + ? WHERE user_id = ? AND symbol = ?", shares, buyer_id, stock_name)
                    else:
                        db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES (?, ?, ?)", buyer_id, stock_name, shares)
                        
                    cash -= (price * shares)
                    db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, buyer_id)
                    db.execute("INSERT INTO histroy (buyer_id, stock_name, shares, price, time, action) VALUES (?, ?, ?, ?, ?, 'buy')", buyer_id, stock_name, shares, price, time)
                        
                    db.execute("COMMIT")
                    session["show_alert"] = True
                    session["alert_message"] = "Successfully Bought!"
                    session["alert_type"] = "success"
                except Exception as e:
                    db.execute("ROLLBACK")
                    print(f"***ERROR*** {e}")

                    session["show_alert"] = True
                    session["alert_message"] = "Transaction Failed!"
                    session["alert_type"] = "danger"
                
            return redirect("/")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    hist = db.execute("SELECT stock_name, shares, price, time, action FROM histroy WHERE buyer_id = ? ORDER BY trans_id DESC LIMIT 35", session["user_id"])
    length = len(hist)

    return render_template("histroy.html", hist=hist, length=length, user_name=db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"], balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    global registration_success

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in & other things...
        session["user_id"] = rows[0]["id"]
        session["show_alert"] = False
        session["alert_message"] = None
        session["alert_type"] = None
        session["selected_symbol"] = None

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        alert_message = None
        if (registration_success):
            alert_message = "Your account has been successfully registered! Please Log In to continue"
            registration_success = False
        return render_template("login.html", alert_message=alert_message)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html", user_name=db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"], balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])
    else:
        symbol = request.form.get("symbol")

        if (not symbol):
            return apology("please enter someting", 403, "/quote")
        
        quote_data = lookup(symbol)
        if (not quote_data):
            return apology(f"cannot find '{symbol}'", 403, "/quote")
        else:
            name = quote_data["name"]
            price = float(quote_data["price"])
            symbol = quote_data["symbol"]

            return render_template("lookup.html", name=name, price=price, symbol=symbol, user_name=db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"], balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    global registration_success

    if request.method == "GET":
        return render_template("register.html")
    else:
        name = request.form.get("username")
        password = request.form.get("password")
        c_password = request.form.get("c_password")

        if (not name or not password or not c_password):
            return apology("must provide username, password and confirm that password", 403, "/register")
        elif (password != c_password):
            return apology("entered password and confirm password should be same", 403, "/register")
        elif (if_already_exists(name)):
            return apology(f"username: '{name}' already exists", 403, "/register")
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", str(name), generate_password_hash(password))
            registration_success = True
            return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":

        stocks = db.execute("SELECT symbol FROM stocks WHERE user_id = ?", session["user_id"])
        length = len(stocks)
        stock_names = []

        if (length != 0):
            for i in range(length):
                stock_names.append(stocks[i]["symbol"])
        
        return render_template("sell.html", length=length, stock_names=stock_names, user_name=db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"], balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])
    else:
        stock_name = request.form.get("symbol")
        shares = int(request.form.get("stock_no"))
        seller_id = int(session["user_id"])
        shares_have = db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", seller_id, stock_name)[0]["shares"]
        quote_data = lookup(stock_name)

        if (not quote_data):
            return apology("invalid symbol", 403, "/sell")
        elif(shares <= 0 or shares > shares_have):
            return apology("invalid shares No.", 403, "/sell")
        else:
            price = float(quote_data["price"])
            seller_id = int(session["user_id"])
            cash = float(db.execute("SELECT cash FROM users WHERE id = ?", seller_id)[0]["cash"])
            time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            try:
                db.execute("BEGIN")

                if (shares_have - shares) == 0:
                    db.execute("DELETE FROM stocks WHERE user_id = ? AND symbol = ?", seller_id, stock_name)
                else:
                    db.execute("UPDATE stocks SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, seller_id, stock_name)
                cash += (price * shares)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, seller_id)
                db.execute("INSERT INTO histroy (buyer_id, stock_name, shares, price, time, action) VALUES (?, ?, ?, ?, ?, 'sell')", seller_id, stock_name, shares, price, time)
                
                db.execute("COMMIT")
                session["show_alert"] = True
                session["alert_message"] = "Successfully Sold!"
                session["alert_type"] = "success"
            except Exception as e:
                print(f"***ERROR*** {e}")

                db.execute("ROLLBACK")
                session["show_alert"] = True
                session["alert_message"] = "Transaction Failed!"
                session["alert_type"] = "danger"
            
            return redirect("/")


@app.route("/profile")
@login_required
def profile():
    user_id = session["user_id"]
    user_name = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    balance = float(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"])
    total_info = db.execute("SELECT price, action, shares FROM histroy WHERE buyer_id = ?", user_id)
    length = len(total_info)
    total_bought = 0
    total_sold = 0
    net = 0
    color = ""

    if (length != 0):
        for i in range(length):
            if (total_info[i]["action"] == "buy"):
                total_bought += float(total_info[i]["price"]) * total_info[i]["shares"]
            else:
                total_sold += float(total_info[i]["price"]) * total_info[i]["shares"]

    net = total_sold - total_bought
    if(net >= 0):
        color = "success"
    else:
        color = "danger"

    return render_template("profile.html", user_id=user_id, user_name=user_name, balance=balance, total_bought=total_bought, total_sold=total_sold, net=net, color=color)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "GET":
        user_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    
        return render_template("change_password.html", user_name=user_name, balance=balance)
    else:
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        prev_password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        if (not current_password or not new_password or not confirm_password):
            return apology("Current Password, New Password and Confirmation Password all are required", 403, "/change_password")
        elif (not check_password_hash(prev_password, current_password)):
            return apology("Current Password is Incorrect", 403, "/change_password")
        elif (new_password != confirm_password):
            return apology("New Password and Confirm Password Should be Same", 403, "/change_password")
        else:
            try:
                db.execute("BEGIN")

                db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])

                db.execute("COMMIT")

                session["show_alert"] = True
                session["alert_message"] = "Password Changed Successfully"
                session["alert_type"] = "success"
            except Exception as e:
                print(f"***ERROR*** {e}")
                db.execute("ROLLBACK")
                session["show_alert"] = True
                session["alert_message"] = "Password Change Failed"
                session["alert_type"] = "danger"

            return redirect("/")


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():

    if request.method == "GET":
        user_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        return render_template("deposit.html", user_name=user_name, balance=balance)
    else:
        deposit_amount = float(request.form.get("deposit_amount"))
        password = request.form.get("password")
        original_password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        if (not deposit_amount or not password):
            return apology("Deposit Amount and Password both are required", 403, "/deposit")
        elif (deposit_amount < 0):
            return apology("Deposit Amount cannot be negative", 403, "/deposit")
        elif (not check_password_hash(original_password, password)):
            return apology("Password is Incorrect", 403, "/deposit")
        else:
            try:
                db.execute("BEGIN")

                db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", deposit_amount, session["user_id"])

                db.execute("COMMIT")
                session["show_alert"] = True
                session["alert_message"] = "Deposit Successful"
                session["alert_type"] = "success"
            except Exception as e:
                print(f"***ERROR*** {e}")
                db.execute("ROLLBACK")

                session["show_alert"] = True
                session["alert_message"] = "Deposit Failed"
                session["alert_type"] = "danger"

            return redirect("/")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():

    if request.method == "GET":
        user_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        
        return render_template("delete.html", user_name=user_name, balance=balance)
    else:
        current_password = request.form.get("current_password")
        text = request.form.get("text")
        original_password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]
        COMMITMENT = "I WANT TO DELETE MY ACCOUNT FOREVER"

        if (not current_password or not text):
            return apology("Your current password and commitment text are required for this process", 403, "/delete")
        elif (not check_password_hash(original_password, current_password)):
            return apology("Password is Incorrect", 403, "/delete")
        elif (text != COMMITMENT):
            return apology("Commitment Text is Incorrect", 403, "/delete")
        else:
            try:
                db.execute("BEGIN")

                db.execute("DELETE FROM stocks WHERE user_id = ?", session["user_id"])
                db.execute("DELETE FROM histroy WHERE buyer_id = ?", session["user_id"])
                db.execute("DELETE FROM users WHERE id = ?", session["user_id"])

                db.execute("COMMIT")
                session.clear()
            except Exception as e:
                print(f"***ERROR*** {e}")
                db.execute("ROLLBACK")
                session["show_alert"] = True
                session["alert_message"] = "Failed to Delete Account"
                session["alert_type"] = "danger"

            return redirect("/")


@app.route("/set_symbol_redirect_buy")
def set_symbol_redirect_buy():
    selected_symbol = request.args.get("symbol")
    session["selected_symbol"] = selected_symbol
    return redirect("/buy")


if __name__ == "__main__":
    app.run(debug=True)
