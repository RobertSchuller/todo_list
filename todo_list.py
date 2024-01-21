import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import re
from datetime import datetime

class UserAuthentication:
    def __init__(self):
        self.users = {}
        self.load_users()

        self.current_user = None
        self.load_tasks()

        self.root = tk.Tk()
        self.root.title("User Authentication")

        # Main Window
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(pady=20)

        tk.Button(self.main_frame, text="Login", command=self.show_login_window).grid(row=0, column=0, padx=10)
        tk.Button(self.main_frame, text="Register", command=self.show_register_window).grid(row=0, column=1, padx=10)

    def load_users(self):
        try:
            with open("users.txt", "r") as file:
                lines = file.readlines()
                for line in lines:
                    username, password_hash = line.strip().split(":")
                    self.users[username] = password_hash
        except FileNotFoundError:
            pass

    def save_users(self):
        with open("users.txt", "w") as file:
            for username, password_hash in self.users.items():
                file.write(f"{username}:{password_hash}\n")

    def load_tasks(self):
        if self.current_user:
            try:
                with open(f"{self.current_user}_tasks.txt", "r") as file:
                    lines = file.readlines()
                    self.current_user_tasks = [line.strip().split("|") for line in lines]
            except FileNotFoundError:
                self.current_user_tasks = []

    def save_tasks(self):
        if self.current_user:
            with open(f"{self.current_user}_tasks.txt", "w") as file:
                for task_info in self.current_user_tasks:
                    file.write(f"{task_info[0]}|{task_info[1]}|{task_info[2]}\n")

    def show_login_window(self):
        login_window = tk.Toplevel(self.root)
        login_window.title("Login")

        tk.Label(login_window, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(login_window, text="Password:").grid(row=1, column=0, padx=10, pady=5)

        self.login_username = tk.StringVar()
        self.login_password = tk.StringVar()

        tk.Entry(login_window, textvariable=self.login_username).grid(row=0, column=1, padx=10, pady=5)
        tk.Entry(login_window, textvariable=self.login_password, show="*").grid(row=1, column=1, padx=10, pady=5)

        tk.Button(login_window, text="Login", command=self.login_and_close(login_window)).grid(row=2, column=0, columnspan=2, pady=10)
        tk.Button(login_window, text="Logout", command=login_window.destroy).grid(row=3, column=0, columnspan=2, pady=10)

    def show_register_window(self):
        register_window = tk.Toplevel(self.root)
        register_window.title("Register")

        tk.Label(register_window, text="New Username:").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(register_window, text="New Password:").grid(row=1, column=0, padx=10, pady=5)

        self.register_username = tk.StringVar()
        self.register_password = tk.StringVar()

        tk.Entry(register_window, textvariable=self.register_username).grid(row=0, column=1, padx=10, pady=5)
        tk.Entry(register_window, textvariable=self.register_password, show="*").grid(row=1, column=1, padx=10, pady=5)

        tk.Button(register_window, text="Register", command=self.register_and_close(register_window)).grid(row=2, column=0, columnspan=2, pady=10)
        tk.Button(register_window, text="Logout", command=register_window.destroy).grid(row=3, column=0, columnspan=2, pady=10)

    def login_and_close(self, window):
        def login():
            username = self.login_username.get()
            password = self.login_password.get()

            if not username or not password:
                messagebox.showwarning("Login Error", "Please enter both username and password.")
                return

            if username in self.users:
                # Hash the provided password and compare with the stored hash
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                if self.users[username] == hashed_password:
                    messagebox.showinfo("Login Successful", "Welcome back, {}".format(username))
                    self.current_user = username
                    self.load_tasks()
                    self.show_task_window()
                    window.destroy()  # Close the login window
                else:
                    messagebox.showwarning("Login Error", "Incorrect password. Please try again.")
            else:
                messagebox.showwarning("Login Error", "Username not found. Please register.")
                
        return login

    def register_and_close(self, window):
        def register():
            new_username = self.register_username.get()
            new_password = self.register_password.get()

            if not new_username or not new_password:
                messagebox.showwarning("Registration Error", "Please enter both username and password.")
                return

            if new_username in self.users:
                messagebox.showwarning("Registration Error", "Username already exists. Please choose another.")
            else:
                # Check password strength
                if not self.is_strong_password(new_password):
                    messagebox.showwarning("Registration Error", "Password should be at least 8 characters long and contain both letters and numbers.")
                    return

                # Hash the password before saving it
                hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                self.users[new_username] = hashed_password
                self.save_users()
                messagebox.showinfo("Registration Successful", "User registered successfully. You can now log in.")
                window.destroy()  # Close the registration window

        return register

    def is_strong_password(self, password):
        # Password should be at least 8 characters long and contain both letters and numbers
        return len(password) >= 8 and re.search(r'\d', password) and re.search(r'[a-zA-Z]', password)

    def show_task_window(self):
        task_window = tk.Toplevel(self.root)
        task_window.title(f"{self.current_user}'s Tasks")

        # Task Entry
        tk.Label(task_window, text="Task:").grid(row=0, column=0, padx=10, pady=5)
        self.task_entry = tk.Entry(task_window, width=30)
        self.task_entry.grid(row=0, column=1, padx=10, pady=5)

        # Due Date Entry
        tk.Label(task_window, text="Due Date (YYYY-MM-DD):").grid(row=1, column=0, padx=10, pady=5)
        self.due_date_entry = tk.Entry(task_window, width=15)
        self.due_date_entry.grid(row=1, column=1, padx=10, pady=5)

        # Priority Entry
        tk.Label(task_window, text="Priority (1-5):").grid(row=2, column=0, padx=10, pady=5)
        self.priority_entry = tk.Entry(task_window, width=5)
        self.priority_entry.grid(row=2, column=1, padx=10, pady=5)

        # Add Task Button
        tk.Button(task_window, text="Add Task", command=self.add_task_and_close(task_window)).grid(row=3, column=0, columnspan=2, pady=10)

        # Task List
        tk.Label(task_window, text="Tasks:").grid(row=4, column=0, padx=10, pady=5)
        self.task_listbox = tk.Listbox(task_window, selectmode=tk.SINGLE, width=40, height=10)
        self.task_listbox.grid(row=4, column=1, padx=10, pady=5)

        # Remove Task Button
        tk.Button(task_window, text="Remove Task", command=self.remove_task).grid(row=5, column=0, columnspan=2, pady=10)

        # Save Tasks Button
        tk.Button(task_window, text="Save Tasks", command=self.save_tasks).grid(row=6, column=0, padx=10, pady=10)

        # Logout Button
        tk.Button(task_window, text="Logout", command=self.logout_and_close(task_window)).grid(row=6, column=1, padx=10, pady=10)

        # Load existing tasks
        for task_info in self.current_user_tasks:
            self.task_listbox.insert(tk.END, f"{task_info[0]} (Due: {task_info[1]}, Priority: {task_info[2]})")

    def add_task_and_close(self, window):
        def add_task():
            task_text = self.task_entry.get()
            due_date = self.due_date_entry.get()
            priority = self.priority_entry.get()

            if task_text and due_date and priority:
                try:
                    # Validate due date format
                    datetime.strptime(due_date, "%Y-%m-%d")

                    # Validate priority
                    priority = int(priority)
                    if 1 <= priority <= 5:
                        task_info = (task_text, due_date, priority)
                        self.current_user_tasks.append(task_info)
                        self.task_listbox.insert(tk.END, f"{task_info[0]} (Due: {task_info[1]}, Priority: {task_info[2]})")
                        self.task_entry.delete(0, tk.END)
                        self.due_date_entry.delete(0, tk.END)
                        self.priority_entry.delete(0, tk.END)
                        
                    else:
                        messagebox.showwarning("Input Error", "Priority should be between 1 and 5.")
                except ValueError:
                    messagebox.showwarning("Input Error", "Invalid date format. Please use YYYY-MM-DD.")
            else:
                messagebox.showwarning("Input Error", "Please fill in all fields.")

        return add_task

    def remove_task(self):
        selected_index = self.task_listbox.curselection()
        if selected_index:
            removed_task = self.current_user_tasks.pop(selected_index[0])
            self.task_listbox.delete(selected_index)
            messagebox.showinfo("Task Removed", f'Task "{removed_task[0]}" removed from the list.')
        else:
            messagebox.showwarning("Selection Error", "Please select a task to remove.")

    def logout_and_close(self, window):
        def logout():
            self.save_tasks()
            self.current_user = None
            window.destroy()
            

        return logout

if __name__ == "__main__":
    app = UserAuthentication()
    app.root.mainloop()
