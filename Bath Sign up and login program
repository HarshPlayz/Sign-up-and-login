import hashlib
import tkinter as tk
from tkinter import messagebox
import sqlite3

conn = sqlite3.connect('Login.db')
c = conn.cursor()

c.execute()
conn.commit()

username = ""
hashed_password = "" 

def storing():
    global username, hashed_password
    c.execute('INSERT INTO login_data VALUES (?, ?)', (username, hashed_password)) 
    conn.commit()

def welcome():
    global existing_account_button, create_account_button

    window = tk.Tk()
    greeting = tk.Label(text="Welcome to my Signup and Login programme", font=("Open Sans", 20))
    greeting.pack()

    existing_account_button = tk.Button(window, text="Existing Account", command=existing_account, width=50, height=20)
    existing_account_button.pack(side=tk.LEFT)

    create_account_button = tk.Button(window, text="Create Account", command=createAccount, width=50, height=20)
    create_account_button.pack(side=tk.LEFT)

    window.mainloop()

def existing_account():
    global userEntry, passwordEntry, submit_button, existing_account_button
    window = tk.Tk()
    label = tk.Label(window, text="Sign in with username")
    label.pack()

    userEntry = tk.Entry(window, width=50)
    userEntry.pack()

    label1 = tk.Label(window, text="Sign in with password")
    label1.pack()

    passwordEntry = tk.Entry(window, width=50, show="*")
    passwordEntry.pack()

    submit_button = tk.Button(window, text="Submit", command=lambda: validate_login(window))
    submit_button.pack()

    existing_account_button.config(state=tk.DISABLED)

def createAccount():
    global userEntry, passwordEntry, submit_button, create_account_button

    window = tk.Tk()
    
    label = tk.Label(window, text="Create a username")
    label.pack()

    userEntry = tk.Entry(window, width=50)
    userEntry.pack()

    label1 = tk.Label(window, text="Create a password")
    label1.pack()

    passwordEntry = tk.Entry(window, width=50, show="*")
    passwordEntry.pack()

    submit_button = tk.Button(window, text="Submit", command=lambda: validate_registration(window))
    submit_button.pack()

    create_account_button.config(state=tk.DISABLED)

def validate_login(parent_window):
    global username, hashed_password
    username = userEntry.get()
    password = passwordEntry.get()

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if check_existing_user(username, hashed_password):
        messagebox.showinfo("showinfo", "Login successful")
        parent_window.destroy()
        existing_account_button.config(state=tk.NORMAL)
    else:
        messagebox.showerror("showerror", "Invalid username or password")
        passwordEntry.delete(0, tk.END)

def validate_registration(parent_window):
    global username, hashed_password, passwordEntry
    username = userEntry.get()
    password = passwordEntry.get()

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    lower, upper, digit, special = 0, 0, 0, 0
    specialchar = "$@_£^*()<>?,!,%"
    for char in passwordEntry.get():
        if char.islower():
            lower += 1
        if char.isupper():
            upper += 1
        if char.isdigit():
            digit += 1
        if char in specialchar:
            special += 1
    
    print(lower, upper, digit, special)
    if lower >= 1 and upper >= 1 and digit >= 1 and special >= 1:
        print("Valid Password")
    else:
        print("Invalid Password")
        messagebox.showerror("showerror", "Error")
        exit()

    if not check_existing_user(username):
        storing()
        messagebox.showinfo("showinfo", "Account created successfully")
        parent_window.destroy()
        create_account_button.config(state=tk.NORMAL)
    else:
        messagebox.showerror("showerror", "Username already exists")

def check_existing_user(username, hashed_password=None):
    if hashed_password:
        c.execute('SELECT * FROM login_data WHERE username = ? AND password = ?', (username, hashed_password))
    else:
        c.execute('SELECT * FROM login_data WHERE username = ?', (username,))
    result = c.fetchone()
    if result:
        return True
    else:
        return False

welcome()
