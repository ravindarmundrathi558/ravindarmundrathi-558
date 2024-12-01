import yara
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Load the YARA rules
rules = yara.compile(source='''
rule embedded_executable {
 meta:
  description = "Detects embedded executable files"
  author = "Ravi"
  date = "2024-10-10"
  version = "1.0"

 strings:
  $exe_signature = { 4D 5A } // PE file signature

 condition:
  $exe_signature at 0
}

rule base64_embedded_executable {
 meta:
  description = "Detects base64-encoded embedded executable files"
  author = "Ravi"
  date = "2023-09-08"
  version = "1.0"

 strings:
  $base64_exe = /([A-Za-z0-9+\/]+=*){50,}/

 condition:
  $base64_exe
}

rule embedded_archive {
 meta:
  description = "Detects embedded archive files"
  author = "Ravindar"
  date = "2023-08-20"
  version = "1.0"

 strings:
  $zip_signature = { 50 4B 03 } 
  $tar_signature = { 75 73 74 61 00 30 }

 condition:
  $zip_signature at 0 or $tar_signature at 0
}

rule malicious_apk_2 {
 meta:
  description = "Detects APK files that are bound to malicious payloads"
  author = "Ravindar"
  date = "2023-08-20"
  version = "1.0"
 strings:
  $s1 = "Ljava/lang/Runtime;" wide
  $s2 = "Ljava/lang/ProcessBuilder;" wide
 condition:
  ($s1 or $s2)
}
''')

def is_malware_yara(file_path):
    try:
        yara_matches = rules.match(filepath=file_path)
        if yara_matches:
            return yara_matches
        return []
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze the file: {e}")
        return []

def analyze_file():
    file_path = filedialog.askopenfilename(title="Select file to analyze", filetypes=[("All Files", "*.*")])
    if file_path:
        progress_var.set(0)
        progress_bar.update()
        for _ in range(10):
            time.sleep(0.1)  # Simulate longer analysis time
            progress_var.set(progress_var.get() + 10)
            progress_bar.update()
        
        yara_matches = is_malware_yara(file_path)
        progress_var.set(100)
        progress_bar.update()
        
        if yara_matches:
            result_label.config(text="Danger! It is a malware.", fg="red")
            details = "\n".join([f"Rule: {match.rule} - Matches: {len(match.strings)}" for match in yara_matches])
            details_label.config(text=details, fg="red")
            log_analysis(file_path, True, details)
            generate_pdf_report(file_path, yara_matches)
        else:
            result_label.config(text="It is not a malware.", fg="green")
            details_label.config(text="No suspicious patterns found.", fg="green")
            log_analysis(file_path, False)
    else:
        messagebox.showwarning("No File Selected", "Please select a file to analyze.")

def log_analysis(file_path, is_malware, details=""):
    with open("analysis_log.txt", "a") as log_file:
        log_file.write(f"File: {file_path} - Malware: {'Yes' if is_malware else 'No'}\n")
        if details:
            log_file.write(f"Details: {details}\n")
        log_file.write("\n")

def generate_pdf_report(file_path, yara_matches):
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{os.path.splitext(os.path.basename(file_path))[0]}_report.pdf")
    c = canvas.Canvas(report_path, pagesize=letter)
    c.setTitle("Malware Analysis Report")

    width, height = letter
    c.drawString(30, height - 30, "Malware Analysis Report")
    c.drawString(30, height - 60, f"File: {file_path}")
    c.drawString(30, height - 90, "YARA Match Details:")

    y = height - 120
    for match in yara_matches:
        c.drawString(30, y, f"Rule: {match.rule}")
        y -= 15
        c.drawString(30, y, f"Matches: {len(match.strings)}")
        y -= 15
        for string in match.strings:
            c.drawString(30, y, f" - {string}")
            y -= 15
        y -= 10
    
    c.save()
    messagebox.showinfo("Report Generated", f"Report saved to {report_path}")

# Create Tkinter root window
root = tk.Tk()
root.title("Malware Analysis")
root.geometry("800x600")

# Styling
root.configure(bg="#f0f0f0")
font_bold = ("Helvetica", 20, "bold")
font_normal = ("Helvetica", 14)

# Main Frame
main_frame = tk.Frame(root, bg="#f0f0f0")
main_frame.pack(expand=True, fill=tk.BOTH)

title_label = tk.Label(main_frame, text="Malware Detection", bg="#f0f0f0", font=("Helvetica", 32, "bold"))
title_label.grid(row=0, column=0, columnspan=2, pady=(20, 20))

button = tk.Button(main_frame, text="Select File", command=analyze_file, font=font_bold, bg="#4CAF50", fg="white")
button.grid(row=1, column=0, pady=(20, 20))

result_label = tk.Label(main_frame, text="", font=font_bold, bg="#f0f0f0")
result_label.grid(row=2, column=0, columnspan=2, pady=20)

details_label = tk.Label(main_frame, text="", font=font_normal, bg="#f0f0f0")
details_label.grid(row=3, column=0, columnspan=2, pady=20)

# Progress bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(main_frame, variable=progress_var, maximum=100)
progress_bar.grid(row=4, column=0, columnspan=2, pady=20, padx=20, sticky="ew")

# Center the widgets horizontally
main_frame.grid_columnconfigure(0, weight=1)

# Center the window on the screen
root.eval('tk::PlaceWindow %s center' % root.winfo_toplevel())

# Run the Tkinter event loop
root.mainloop()
