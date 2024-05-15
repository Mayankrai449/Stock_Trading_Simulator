import os
import sqlite3
import re

from cs50 import SQL
from flask import Flask, make_response, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.template_filter('format_currency')
def format_currency(value):
    return "${:,.2f}".format(value)


def is_non_digit(input_str):
    return bool(re.search(r'\D', input_str))


def table_exists(table_name):
    conn = sqlite3.connect("finance.db")
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    table = cursor.fetchone()

    conn.close()

    return table is not None


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
    username = session.get('username')

    cash_res = db.execute("SELECT cash FROM users WHERE username = ?", username)
    first_row = cash_res[0]
    cashm = first_row['cash']
    cash = "${:,.2f}".format(cashm)

    if table_exists(username):
        portfolio = db.execute("SELECT * FROM ?", username)
        total_res = db.execute("SELECT SUM(total) FROM ?", username)

        if total_res is not None and total_res[0]['SUM(total)'] is not None:
            totalf = float(total_res[0]['SUM(total)'])
            totalf = totalf + cashm
            total = "${:,.2f}".format(totalf)
        else:
            total = cash

        return render_template("index.html",
                               portfolio=portfolio,
                               username=username,
                               total=total,
                               cash=cash)
    else:
        return render_template("index.html",
                               username=username,
                               total=cash,
                               cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    username = session.get('username')

    cash_res = db.execute("SELECT cash FROM users WHERE username = ?", username)
    first_row = cash_res[0]
    cashm = first_row['cash']
    cash = "${:,.2f}".format(cashm)

    cash = cash.replace('$', '').replace(',', '')
    cash = float(cash)

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Missing Symbol", 400)
        elif not request.form.get("shares"):
            return apology("Missing Shares", 400)
        else:
            sym = request.form.get("symbol")
            share = request.form.get("shares")

            if is_non_digit(share):
                return apology("Invalid share input", 400)

            res = lookup(sym)
            if res:
                price = res["price"]
            else:
                return apology("Invalid Symbol", 400)

            total_price = price*float(share)

            if total_price > cash:
                return apology("Unaffordable", 400)
            else:

                new_cash = cash - total_price
                print("new", new_cash)

                if not table_exists(username):
                    db.execute(
                        "CREATE TABLE ? (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, price REAL NOT NULL, shares REAL NOT NULL, total REAL NOT NULL)", username)

                stock_check = db.execute("SELECT symbol FROM ?", username)
                exists = False
                for row in stock_check:
                    if sym in row.values():
                        exists = True
                        break

                if exists:
                    db.execute("UPDATE ? SET shares = shares + ?, total = total + ? WHERE symbol = ?",
                               username, share, total_price, sym)
                else:
                    db.execute("INSERT INTO ? (symbol, price, shares, total) VALUES (?, ?, ?, ?)",
                               username, sym, price, share, total_price)

                db.execute("UPDATE users SET cash = ? WHERE username = ?", new_cash, username)
                portfolio = db.execute("SELECT * FROM ?", username)

            cash = "${:,.2f}".format(new_cash)

            total_res = db.execute("SELECT SUM(total) FROM ?", username)
            totalf = float(total_res[0]['SUM(total)'])
            totalf = totalf + new_cash
            total = "${:,.2f}".format(totalf)

            table_name = f"{username}_history"
            shares_with_sign = f"+{share}"

            db.execute(
                f"CREATE TABLE IF NOT EXISTS {table_name} (id INTEGER PRIMARY KEY, symbol TEXT NOT NULL, bought TEXT NOT NULL, shares REAL NOT NULL, price REAL NOT NULL, transacted TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            db.execute(f"INSERT INTO {table_name} (symbol, bought, shares, price) VALUES (?, 'Bought!', ?, ?)",
                       sym, shares_with_sign, price)

        return render_template("index.html",
                               total=total,
                               bought=True,
                               username=username,
                               cash=cash,
                               portfolio=portfolio)
    else:
        return render_template("buy.html",
                               username=username)


@app.route("/history")
@login_required
def history():
    username = session.get("username")

    table_name = f"{username}_history"

    history = db.execute(f"SELECT * FROM {table_name}")

    return render_template("history.html",
                           username=username,
                           history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide Username")
            return render_template("login.html"), 400

        # Ensure password was submitted

        elif not request.form.get("password"):
            flash("Must provide Password")
            return render_template("login.html"), 400

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            flash("Invalid username/password")
            return render_template("login.html"), 400

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        id = session["user_id"]

        use_res = db.execute("SELECT username FROM users WHERE id = ?", id)
        first_row = use_res[0]
        username = first_row['username']

        cash_res = db.execute("SELECT cash FROM users WHERE username = ?", username)
        first_row = cash_res[0]
        cashm = first_row['cash']
        cash = "${:,.2f}".format(cashm)

        session['username'] = username
        session['cash'] = cash

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    username = session.get('username')
    if request.method == "POST":
        sym = request.form.get("symbol")
        res = lookup(sym)
        if res:
            symbol = res["symbol"]
            price = "{:.2f}".format(res["price"])
            name = res["name"]

            return render_template("quote.html",
                                   username=username,
                                   submitted=True,
                                   name=name,
                                   symbol=symbol,
                                   price=price)

        else:
            return apology("Invalid symbol", 400)

    else:
        return render_template("quote.html",
                               username=username)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        password_pattern = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
        if not request.form.get("username"):
            return apology("Please enter username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Please enter password", 400)
        elif not password_pattern.match(request.form.get("password")):
            return apology("Password must contain 8 characters with mix of numbers and symbols", 400)

        elif not request.form.get("confirmation"):
            return apology("Confirm Password", 400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Password does not match", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) == 1:
            return apology("User already exists!", 400)
        else:
            username = request.form.get("username")
            password = generate_password_hash(request.form.get("confirmation"))
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password)
            registered = True

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        session["user_id"] = rows[0]["id"]
        id = session["user_id"]

        use_res = db.execute("SELECT username FROM users WHERE id = ?", id)
        first_row = use_res[0]
        username = first_row['username']

        cash_res = db.execute("SELECT cash FROM users WHERE username = ?", username)
        first_row = cash_res[0]
        cashm = first_row['cash']
        cash = "${:,.2f}".format(cashm)

        session['username'] = username
        session['cash'] = cash

        return render_template("index.html",
                               registered=registered,
                               username=username,
                               cash=cash)

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    username = session.get("username")
    sym = db.execute("SELECT symbol FROM ?", username)
    symbols = [item['symbol'] for item in sym]

    if request.method == "POST":

        symb = request.form.get('symbol')
        shares = request.form.get('shares')

        if is_non_digit(shares):
            return apology("Invalid share input", 400)

        share_check = db.execute("SELECT shares from ? WHERE symbol = ?", username, symb)

        if share_check:
            old_share = [item['shares'] for item in share_check][0]
        else:
            return apology("No shares found", 400)

        price_check = db.execute("SELECT price FROM ? WHERE symbol = ?", username, symb)
        old_price = [item['price'] for item in price_check][0]

        data = lookup(symb)
        if data:
            new_price = data["price"]

        new_total = old_price*(old_share - float(shares))

        print(new_total)

        if float(shares) > old_share:
            return apology("Not enough shares", 400)
        else:
            db.execute("UPDATE ? SET shares = shares - ?, total = ? WHERE symbol = ?", username, shares, new_total, symb)

        cash_res = db.execute("SELECT cash FROM users WHERE username = ?", username)
        first_row = cash_res[0]
        cashm = first_row['cash']
        cash = "${:,.2f}".format(cashm)

        cash = cash.replace('$', '').replace(',', '')
        cash = float(cash)

        old_total = old_price*old_share
        new_cash = cash + (new_price * float(shares))
        db.execute("UPDATE users SET cash = ? WHERE username = ?", new_cash, username)
        cash = "${:,.2f}".format(new_cash)

        total_res = db.execute("SELECT SUM(total) FROM ?", username)
        totalf = float(total_res[0]['SUM(total)'])
        totalf = totalf + new_cash
        total = "${:,.2f}".format(totalf)

        db.execute("DELETE FROM ? WHERE shares < 1 OR shares = 0", username)

        table_name = f"{username}_history"
        shares_with_sign = f"-{shares}"

        db.execute(
            f"CREATE TABLE IF NOT EXISTS {table_name} (id INTEGER PRIMARY KEY, symbol TEXT NOT NULL, bought TEXT NOT NULL, shares REAL NOT NULL, price REAL NOT NULL, transacted TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        db.execute(f"INSERT INTO {table_name} (symbol, bought, shares, price) VALUES (?, 'Sold!', ?, ?)",
                   symb, shares_with_sign, new_price)

        portfolio = db.execute("SELECT * FROM ?", username)

        return render_template("index.html",
                               sold=True,
                               total=total,
                               cash=cash,
                               username=username,
                               portfolio=portfolio
                               )
    else:
        return render_template("sell.html",
                               username=username,
                               symbols=symbols,
                               )


if __name__ == '__main__':
    app.run(debug=True, port=8081)
