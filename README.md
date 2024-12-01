# Malware_Analysis_Yara
Malware Analysis Tool
Overview

The Malware Analysis Tool is a Python-based application designed to detect malware in files using YARA rules. It features a user-friendly graphical interface for selecting files, a progress bar to indicate the analysis status, and generates detailed PDF reports of the analysis results.
Features

    YARA Integration: Uses YARA rules to identify various types of malware including embedded executables, base64-encoded files, archives, and malicious APKs.
    User-Friendly GUI: Built with Tkinter, the GUI allows easy file selection and displays the results clearly.
    Progress Indicator: A progress bar provides feedback during the file analysis.
    Detailed PDF Reports: Generates comprehensive PDF reports using ReportLab, detailing the analysis results.
    Logging: Maintains logs of all analyses, including file details and malware detection status.

How It Works

    File Selection: Users select a file through the GUI.
    Analysis: The file is analyzed using predefined YARA rules to detect malicious patterns.
    Results Display: The analysis results are displayed in the GUI.
    PDF Report Generation: A detailed PDF report is generated and saved in the same directory as the script.
    Logging: Analysis results are logged in a text file for future reference.

Getting Started
Prerequisites

    Python 3.x
    YARA Python library
    Tkinter
    ReportLab

Installation

    Clone the repository:

    bash

git clone https://github.com/ravindarmundrathi558/Malware_Analysis_Yara
cd malware-analysis-tool

Install the required Python libraries:

bash

    pip install yara-python reportlab

Running the Tool

Run the Python script to start the GUI:

bash

python malware_analysis_tool.py

Code Explanation
YARA Rules

The tool uses YARA rules to detect various types of malware. The rules are compiled at the start of the script:

python

rules = yara.compile(source=''' ... ''')

Functions

    is_malware_yara(file_path): Matches the file against the YARA rules and returns the results.
    analyze_file(): Handles file selection, calls the analysis function, updates the progress bar, and displays the results.
    log_analysis(file_path, is_malware, details=""): Logs the analysis results to a text file.
    generate_pdf_report(file_path, yara_matches): Generates a PDF report of the analysis results.

GUI Components

    Title Label: Displays the title of the application.
    Select File Button: Opens a file dialog to select a file for analysis.
    Result Label: Displays whether the file is malware or not.
    Details Label: Displays details of the YARA matches.
    Progress Bar: Shows the progress of the file analysis.

Progress Indicator

The progress bar simulates longer analysis time to provide a better user experience:

python

for _ in range(10):
    time.sleep(0.1)
    progress_var.set(progress_var.get() + 10)
    progress_bar.update()

PDF Report Generation

The tool generates a detailed PDF report using the ReportLab library:

python

def generate_pdf_report(file_path, yara_matches):
    ...
    c.save()
