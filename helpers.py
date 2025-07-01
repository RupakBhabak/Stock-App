import requests

from flask import redirect, render_template, session
from functools import wraps

from cs50 import SQL
db = SQL("sqlite:///finance.db")

def apology(message, code=400, back_link="/login"):
    """Render message as an apology to user."""

    return render_template("apology.html", message=message, code=code, back_link=back_link)


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""
    url = f"https://finance.cs50.io/quote?symbol={symbol.upper()}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for HTTP error responses
        quote_data = response.json()
        return {
            "name": quote_data["companyName"],
            "price": quote_data["latestPrice"],
            "symbol": symbol.upper()
        }
    except requests.RequestException as e:
        print(f"Request error: {e}")
    except (KeyError, ValueError) as e:
        print(f"Data parsing error: {e}")
    return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

def if_already_exists(name):
    find = db.execute("SELECT username FROM users WHERE username = ?", name)
    if (not find):
        return False
    else:
        return True

def owns_stock(user_id, symbol):
    rows = db.execute("SELECT * FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)
    return (len(rows) > 0)
