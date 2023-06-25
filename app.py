import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///jukebox.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET"])
@login_required
def homepage():
    # When user enters website and they're already logged in, direct them to the Discover tab
    user_id = session["user_id"]
    entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE privacy = 0 AND users.user_id != ? ORDER BY time DESC", user_id)
    return render_template("discover.html", entries=entries)


@app.route("/index", methods=["GET", "POST"])
@login_required
def index():
    """Update user's profile and display the current user's profile"""

    user_id = session["user_id"]

    # With POST, access the new updated profile pic and update main profile
    if request.method == "POST":
        # Get the profile pic that the user wants to change to
        profilepic = request.form.get("profilepic")

        # Remove old profile pic and then insert new one into the database
        db.execute("DELETE FROM profile WHERE user_id = ?", user_id)
        db.execute("INSERT INTO profile (user_id, picture) VALUES (?, ?)", user_id, profilepic)

        # Render the new main profile with new profile pic
        profile = db.execute("SELECT * FROM profile JOIN users ON users.user_id = profile.user_id WHERE profile.user_id = ?", user_id)
        return render_template("mainprofile.html", profile=profile)

    else:
        # Display the users own account
        profile = db.execute("SELECT * FROM profile JOIN users ON users.user_id = profile.user_id WHERE profile.user_id = ?", user_id)
        return render_template("mainprofile.html", profile=profile)


@app.route("/showentries", methods=["POST"])
@login_required
def showentries():
    """Show the entries of the user w/ user_id"""

    user_id = request.form.get("user_id")

    # Select the entries of the user that was clicked (since the entries are clickable to become expandable)
    entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE privacy = 0 AND users.user_id = ? ORDER BY time DESC", user_id)

    # Select the username of the user who made the entry
    username = db.execute("SELECT username FROM users WHERE users.user_id = ?", user_id)

    return render_template("publicprofile.html", entries=entries, username=username)


@app.route("/displayprofile<int:user_id>", methods=["GET"])
@login_required
def displayprofile(user_id):
    """Display user's profile"""

    # Get the entry info based off of the user_id
    profile = db.execute("SELECT * FROM profile JOIN users ON users.user_id = profile.user_id WHERE profile.user_id = ?", user_id)
    return render_template("index.html", profile=profile)


@app.route("/editprofile", methods=["GET", "POST"])
@login_required
def editprofile():
    """Show the page to let user edit their profile pic"""

    if request.method == "GET":
        return render_template("editprofile.html")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Allow user to search for another user"""

    # User hits the search button
    if request.method == "POST":
        # SQL command checks to see if any of the users input is like any of the existing usernames
        users = db.execute("SELECT * FROM users WHERE username LIKE ?", "%" + request.form.get("search-input") + "%")
        # redirects to a template with the results of the usernames that matched with the user's search
        return render_template("results.html", users=users)

    else:
        # When the user clicks the search tab, allow them to enter a username into the search bar
        return render_template("search.html")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    """Create an entry"""

    user_id = session["user_id"]

    if request.method == "GET":
        return render_template("create.html")

    else:
        # Get all the inputs from the entry
        song_name = request.form.get("song-name")
        artist_name = request.form.get("artist-name")
        genre = request.form.get("genre")
        entry = request.form.get("entry")
        privacy = request.form.get("privacy")
        now = datetime.now()
        format_now = now.strftime('%Y-%m-%d %H:%M:%S')

        # Check if user filled out all the required inputs
        if len(song_name) == 0 or len(artist_name) == 0 or len(entry) == 0:
            # Return apology if user didn't
            return apology("Please fill out all the required spots", 400)

        # Record all the info inputted by user
        db.execute("INSERT INTO artists (artist_name) VALUES (?)", artist_name)
        artist_id = db.execute("SELECT artist_id FROM artists WHERE artist_name = ?", artist_name)

        db.execute("INSERT INTO songs (song_name, genre, artist_id) VALUES (?, ?, ?)", song_name, genre, artist_id[0]["artist_id"])
        song_id = db.execute("SELECT song_id FROM songs WHERE song_name = ?", song_name)

        db.execute("INSERT INTO entries (user_id, time, input, privacy, song_id) VALUES (?, ?, ?, ?, ?)", user_id, format_now, entry, privacy, song_id[0]["song_id"])

        # Redirect user to the profile function that renders profile
        return redirect("/profile")


@app.route("/follow", methods=["POST"])
@login_required
def follow():
    """Follow a user"""

    # Get the followng_id of the account that the user wants to unfollow
    followinguser_id = request.form.get("user_id")

    user_id = session["user_id"]

    # Checks if user already followed this person
    check = db.execute("SELECT * FROM follows WHERE user_id = ? AND following_id = ?", user_id, followinguser_id)

    # If user does, check will be true
    if check:
        # Return apology if user has already followed this user
        return render_template("apology4.html")

    else:
        # Since the user hasn't been followed, add it to the follows table
        db.execute("INSERT INTO follows (user_id, following_id) VALUES (?, ?)", user_id, followinguser_id)
        return redirect("/feed")


@app.route("/unfollow", methods=["POST"])
@login_required
def unfollow():
    """Unfollow a user"""

    # Get the followng_id of the account that the user wants to unfollow
    following_id = request.form.get("following_id")

    user_id = session["user_id"]

    # Delete the row from the follows table where the previous info aligns and redirect user to updated feed
    db.execute("DELETE FROM follows WHERE follows.user_id = ? AND follows.following_id = ?", user_id, following_id)
    return redirect("/feed")


@app.route("/followedprofile<int:user_id>", methods=["GET"])
@login_required
def followedprofile(user_id):
    """Render profile for a followed user"""

    # Get profile info from profile table w/ user_id
    profile = db.execute("SELECT * FROM profile JOIN users ON users.user_id = profile.user_id WHERE profile.user_id = ?", user_id)

    # Render a profile with an unfollow button instead of a follow button b/c the user is already followed
    return render_template("profilefollowed.html", profile=profile)


@app.route("/feed", methods=["GET"])
@login_required
def feed():
    """Display entries of those current user followed"""
    user_id = session["user_id"]
    # Get all the following_id that's associated with the user_id (or current user
    entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id JOIN follows ON follows.following_id = users.user_id WHERE privacy = 0 AND follows.user_id = ? ORDER BY time DESC", user_id)
    return render_template("followingfeed.html", entries=entries)


@app.route("/filter", methods=["POST"])
@login_required
def filter():
    """Filter through the discover tab by genre"""
    user_id = session["user_id"]

    if request.method == "POST":
        # Gets the user input from the filter html
        genre = request.form.get("filter-genre")
        # Get the entries with that genre
        entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE privacy = 0 AND songs.genre = ? ORDER BY time DESC", genre)

        # If user wants ALL genres
        if genre == "All":
            # Get all entries and display it
            entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE privacy = 0 ORDER BY time DESC")
            return render_template("discover.html", entries=entries)

        # If no entries have been made with that genre, render an apology (apology2)
        if len(entries) == 0:
            return render_template("apology2.html")

        # Display filtered entries
        return render_template("filter.html", entries=entries)


@app.route("/discover", methods=["GET"])
@login_required
def discover():
    """Show history of entries"""
    user_id = session["user_id"]

    if request.method == "GET":
        # Get all entries and display it by date and time
        entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE privacy = 0 AND users.user_id != ? ORDER BY time DESC", user_id)
        return render_template("discover.html", entries=entries)


@app.route("/entryfull<int:entry_id>", methods=["GET"])
@login_required
def entryfull(entry_id):
    """ Display the full entry to the entry w/ the entry_id """

    if request.method == "GET":
        # Get all the info of the entry w/ the entry_id and display it on a nicely designed form
        entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE entries.id = ? ORDER BY time DESC", entry_id)
        return render_template("entryfull.html", entries=entries)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username = request.form.get("username")
        username = username.lower()
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/discover")

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


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    """Show current's profile"""

    user_id = session["user_id"]

    if request.method == "GET":
        # Get all the entries made by the current user and render template w/ it
        entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE users.user_id = ? ORDER BY time DESC", user_id)
        return render_template("myradio.html", entries=entries)


@app.route("/favorited<int:entry_id>", methods=["GET"])
@login_required
def favorited(entry_id):
    """Add an entry to user's favorites table"""

    user_id = session["user_id"]

    if request.method == "GET":
        # Checks if user already favorited entry
        check = db.execute("SELECT * FROM favorites WHERE user_id = ? AND entry_id = ?", user_id, entry_id)

        # If user does, check will be true
        if check:
            # Return apology if user has already favorited it
            return render_template("apology3.html")
        else:
            # Since the entry has not been favorited, add it to the favorites table
            db.execute("INSERT INTO favorites (user_id, entry_id) VALUES (?, ?)", user_id, entry_id)

        # Redirect to /favorites function to render template
        return redirect("/favorites")


@app.route("/unfavorited<int:entry_id>", methods=["GET"])
@login_required
def unfavorited(entry_id):
    """Delete a favorited post from the favorites table. This is called by the entryfullfavorited.html template."""

    # Delete favorited entry and then redirect ot the favorites page using /favorites
    db.execute("DELETE FROM favorites WHERE favorites.entry_id = ?", entry_id)
    return redirect("/favorites")


@app.route("/entryfullfavorited<int:entry_id>", methods=["GET"])
@login_required
def entryfullfavorited(entry_id):
    """Render an entryfull template for favorited entries only so the favorite button becomes unfavorited"""

    if request.method == "GET":
        print(entry_id)
        # Get all the info of the entry w/ the entry_id and display it on a nicely designed form
        entries = db.execute("SELECT * FROM entries JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id JOIN users ON entries.user_id = users.user_id WHERE privacy = 0 AND entries.id = ? ORDER BY time DESC", entry_id)
        return render_template("entryfullfavorited.html", entries=entries)


@app.route("/favorites", methods=["GET"])
@login_required
def favorites():
    """Display user's favorited entries"""

    user_id = session["user_id"]

    if request.method == "GET":
        # Get all the entries that the user favorited and return template
        favorited_entries = db.execute("SELECT * FROM entries JOIN favorites ON entries.id = favorites.entry_id JOIN users ON entries.user_id = users.user_id JOIN songs ON entries.song_id = songs.song_id JOIN artists ON songs.artist_id = artists.artist_id WHERE favorites.user_id = ? ORDER BY time DESC", user_id)
        return render_template("favorites.html", favorited_entries=favorited_entries)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Function used to check if password has at least 1 number
    def passwordHasNumber(password):
        for char in password:
            if char.isdigit():
                return True
        return False

    # Function used to check if password has at least 1 letter
    def passwordHasLetter(password):
        for char in password:
            if char.isalpha():
                return True
        return False

    # User reached route via POST (as by submitting a register form via POST)
    if request.method == "POST":

        # Get user's inputs
        username = request.form.get("username")
        username = username.lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Use SQL query to check whether the username already exists
        check = db.execute("SELECT username FROM users WHERE username = ?", username)

        # Check if user's input passes every test, and if yes, register them
        if len(password) == 0 or len(username) == 0:
            # Return apology if user didn't input a password or username
            return apology("we said input a password and user!!", 400)

        # Our Personal Touch: Makes sure that the password has at least 1 number and symbol and min length of 8 characters
        if len(password) < 8:
            return apology("password TOO weak, make it 8 characters NOW", 400)

        if not passwordHasNumber(password):
            return apology("password TOO weak, add a NUMBER NOW", 400)

        if not passwordHasLetter(password):
            return apology("password TOO weak, add a LETTER NOW", 400)
        # Check if password has at least one special character
        if password.isalnum():
            return apology("password TOO weak, add a SPECIAL CHARACTER NOW", 400)

        # Check if password confirm is correct, if not, register them
        if password != confirmation:
            # Return apology if confirmed password wasn't correct
            return apology("close but confirmed password wasn't correct :/ ", 400)

        # Check if username already exists
        if check:
            # Return apology if check is true (b/c the username was found in the database)
            return apology("too slow, username was already taken", 400)

        else:
            # Hash password
            hash = generate_password_hash(password)
            # Insert username and a hashed password into users table
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
            # Get new user's id
            new_user = db.execute("SELECT user_id FROM users WHERE username = ?", username)
            session["user_id"] = new_user[0]["user_id"]
            # Get user's profile pic and add it to table
            profilepic = request.form.get("profilepic")
            db.execute("INSERT INTO profile (user_id, picture) VALUES (?, ?)", new_user[0]["user_id"], profilepic)
            # Direct to homepage
            return redirect("/index")

    # Render registration page if user wants to access it thru GET
    else:
        return render_template("registration.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)