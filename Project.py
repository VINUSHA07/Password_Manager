# Import necessary libraries
import tkinter as tk  # GUI library
from tkinter import ttk  # Themed Tkinter widgets
import sqlite3  # Database library
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Password-based Key Derivation Function 2
from cryptography.hazmat.primitives import hashes  # Cryptographic hash functions
from cryptography.hazmat.backends import default_backend  # Backend for cryptography operations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Cryptography algorithms and modes
from base64 import urlsafe_b64encode, urlsafe_b64decode  # Encoding and decoding in base64
import os  # Operating system functions
import string  # String operations
import secrets  # Cryptographically strong random numbers


# Database connection
conn = sqlite3.connect('C:/Users/19015/OneDrive/Desktop/IS_Final_Project/IS Database/GarlapatiDB.db')
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS Passwords (
                Website_Name VARCHAR(30),
                User_Name VARCHAR(30),
                Password VARCHAR(100)
            )''')

# Function to add password data to the database
def add_to_database(website, username, password):
    c.execute("INSERT INTO Passwords (Website_Name, User_Name, Password) VALUES (?, ?, ?)", (website, username, password))
    conn.commit()

master_password = None  # Initialize master password variable

# Function to generate strong and random passwords
def generate_random_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(15))  # Generate a 15-character password
    return password

# Function to derive a key from the master password using PBKDF2 algorithm
def derive_key_from_master_password(master_password):
    password_bytes = master_password.encode('utf-8')
    salt = os.urandom(16)  # Use a unique salt
    iterations = 100000  # Adjust as needed
    length = 32  # 256-bit key length

    # Key Derivation Function (PBKDF2) setup
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    derived_key = kdf.derive(password_bytes)  # Derive key from the password
    return derived_key, salt  # Return derived key and salt

# Function to encrypt passwords using AES algorithm
def encrypt_password(password, key, salt):
    iv = os.urandom(16)  # Generate Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # AES Cipher setup
    encryptor = cipher.encryptor()  # Encryptor object

    encrypted_password = iv + encryptor.update(password.encode('utf-8')) + encryptor.finalize()  # Encrypt password
    return urlsafe_b64encode(encrypted_password), salt  # Return encrypted password and salt

# Function to decrypt passwords using AES algorithm
def decrypt_password(encrypted_password, key, salt):
    iv = encrypted_password[:16]  # Extract IV from the encrypted password
    encrypted_password = urlsafe_b64decode(encrypted_password)  # Decode base64 encrypted password
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # AES Cipher setup
    decryptor = cipher.decryptor()  # Decryptor object

    decrypted_password = decryptor.update(encrypted_password[16:]) + decryptor.finalize()  # Decrypt password
    return decrypted_password.decode('utf-8')  # Return decrypted password

# Function to set the master password
def set_master_password():
    global master_password
    password = password_entry.get()  # Get password from user input
    confirm_password = confirm_password_entry.get()  # Get confirmation password from user input

    if password == confirm_password:
        master_password = password  # Set the master password
        instruction_label.config(text="Please enter your Master Password for login", fg="black")
        confirm_password_label.grid_forget()  # Hide confirm password label
        confirm_password_entry.grid_forget()  # Hide confirm password entry
        set_password_button.grid_forget()  # Hide set password button
        login_button.grid(row=3, column=1, padx=10, pady=5)  # Show login button
        password_entry.delete(0, tk.END)  # Clear password entry field
        confirm_password_entry.delete(0, tk.END)  # Clear confirm password entry field
    else:
        instruction_label.config(text="Passwords do not match. Please try again.", fg="red")

# Function to open the password manager window
def open_password_manager():
    global master_password
    password_manager_window = tk.Tk()  # Create password manager window
    password_manager_window.title("Password Manager")
    password_manager_window.geometry("400x200")

    welcome_label = tk.Label(password_manager_window, text="Welcome to Password Manager", font=("Arial", 14), pady=10)
    welcome_label.pack()

    # Create a frame to hold the buttons
    button_frame = tk.Frame(password_manager_window)
    button_frame.pack()

    # Function to add a password
    def add_password():
        derived_key, salt = derive_key_from_master_password(master_password)
        open_password_entry_window(derived_key, salt)

    # Function to view passwords
    def view_passwords():
        c.execute("SELECT * FROM Passwords")
        rows = c.fetchall()

        view_passwords_window = tk.Toplevel(password_manager_window)
        view_passwords_window.title("View Passwords")

        tree = ttk.Treeview(view_passwords_window, columns=("Website", "Username", "Password"), show='headings')
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")

        for row in rows:
            tree.insert("", "end", values=row)

        tree.pack()

        view_passwords_window.mainloop()

    # Add Password button setup
    add_password_button = tk.Button(button_frame, text="Add Password", command=add_password)
    add_password_button.pack(side=tk.LEFT, padx=10)  # Add horizontal padding between buttons

    # View Passwords button setup
    view_password_button = tk.Button(button_frame, text="View Passwords", command=view_passwords)
    view_password_button.pack(side=tk.LEFT, padx=10, pady=10)  # Add horizontal and vertical padding between buttons

    # Labels to provide instructions for users
    instruction_label = tk.Label(password_manager_window, text="Add Password button enables you to store new passwords", font=("Arial", 10), pady=10)
    instruction_label.pack()

    instruction_label = tk.Label(password_manager_window, text="View Password button enables you to view encrypted passwords", font=("Arial", 10), pady=10)
    instruction_label.pack()

    password_manager_window.mainloop()

# Function for user login
def login():
    global master_password
    entered_password = password_entry.get()  # Get entered password

    if entered_password == master_password:  # Check if entered password matches master password
        instruction_label.config(text="Login successful!", fg="green")
        derived_key, salt = derive_key_from_master_password(master_password)
        window.destroy()
        open_password_manager()
        
    # Function to display an error message for incorrect password
    else:   
        instruction_label.config(text="Incorrect password. Please try again.", fg="red")


# Function to open the password entry window
def open_password_entry_window(key, salt):

    #Defining the function to get details from user
    def add_passwords():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        #Calling the Encrypted function to encrypt the password and also sending it to database
        encrypted_password, encrypted_salt = encrypt_password(password, key, salt)
        add_to_database(website, username, encrypted_password.decode('utf-8'))
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        password_entry_window.destroy()

    #Defining the function to generate passwords
    def generate_password():
        random_password = generate_random_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, random_password)

    #Defining the function to show and hide the password
    def toggle_password_visibility():
        current_state = password_entry["show"]
        if current_state == "*":
            password_entry.config(show="")
            show_password_button.config(text="Hide Password")

        else:
            password_entry.config(show="*")
            show_password_button.config(text="Show Password")

    # Create a new window for entering passwords
    password_entry_window = tk.Tk()
    password_entry_window.title("Add_Passwords")
    password_entry_window.geometry("370x250")

    # Labels and Entry fields for website, username, and password
    instruction_label = tk.Label(password_entry_window, text="Please Enter your passwords", font=("Arial", 12), pady=10)
    instruction_label.grid(row=0, column=0, columnspan=4, padx=10, pady=5, sticky="nsew")

    website_label = tk.Label(password_entry_window, text="Website:")
    website_label.grid(row=1, column=0, padx=10, pady=5)
    website_entry = tk.Entry(password_entry_window)
    website_entry.grid(row=1, column=1, padx=10, pady=5)

    username_label = tk.Label(password_entry_window, text="Username:")
    username_label.grid(row=2, column=0, padx=10, pady=5)
    username_entry = tk.Entry(password_entry_window)
    username_entry.grid(row=2, column=1, padx=10, pady=5)

    password_label = tk.Label(password_entry_window, text="Password:")
    password_label.grid(row=3, column=0, padx=10, pady=5)
    password_entry = tk.Entry(password_entry_window, show="*")
    password_entry.grid(row=3, column=1, padx=10, pady=5)
  
    # Button to show or hide password
    show_password_button = tk.Button(password_entry_window, text="Show Password", command=toggle_password_visibility)
    show_password_button.grid(row=4, column=1, padx=10, pady=5)

    # Button to generate a random password
    generate_password_button = tk.Button(password_entry_window, text="Generate Password", command=generate_password)
    generate_password_button.grid(row=3, column=2, padx=10, pady=5)
  
    # Button to submit entered passwords
    add_password_button = tk.Button(password_entry_window, text="Submit", command=add_passwords)
    add_password_button.grid(row=5, column=1, padx=10, pady=5)

    # Start the window's event loop
    password_entry_window.mainloop()

# Create the main Tkinter window
window = tk.Tk()
window.title("Password Manager")
window.configure(bg="#d3d3d3")
window.geometry("400x200")

# Create a frame within the main window for content
center_frame = tk.Frame(window, bg="#d3d3d3")
center_frame.grid(row=0, column=0, padx=50, pady=38)

# Labels, Entry fields, and buttons for setting master password and login
instruction_label = tk.Label(center_frame, text="Please set your Master Password", font=("Arial", 12), bg="#d3d3d3")
instruction_label.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

password_label = tk.Label(center_frame, text="Master Password", bg="#d3d3d3")
password_label.grid(row=1, column=0, padx=10, pady=5)
password_entry = tk.Entry(center_frame, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)

confirm_password_label = tk.Label(center_frame, text="Confirm Password", bg="#d3d3d3")
confirm_password_label.grid(row=2, column=0, padx=10, pady=5)
confirm_password_entry = tk.Entry(center_frame, show="*")
confirm_password_entry.grid(row=2, column=1, padx=10, pady=5)

set_password_button = tk.Button(center_frame, text="Set Master Password", command=set_master_password)
set_password_button.grid(row=3, column=1, padx=10, pady=5)

login_button = tk.Button(center_frame, text="Login", command=login)


window.mainloop()  # Start the Tkinter event loop

conn.close()  # Close the database connection when done
