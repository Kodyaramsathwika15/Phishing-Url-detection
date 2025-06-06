import tkinter as tk
from tkinter import scrolledtext, messagebox, font
from phishing_detector import is_suspicious_url
from virustotal_api import check_virustotal

API_KEY = "  "# your api_key

def analyze_url_gui():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input error", "Please enter a URL")
        return
    
    output_text.config(state='normal')
    output_text.delete('1.0', tk.END)
    output_text.insert(tk.END, f"Analyzing: {url}\n")

    if is_suspicious_url(url):
        output_text.insert(tk.END, "⚠️ Rule-based warning: URL looks suspicious.\n")

    result = check_virustotal(url, API_KEY)
    if "malicious" in result and result["malicious"] > 0:
        output_text.insert(tk.END, f"🚨 VirusTotal says: {result['malicious']} engines flagged this as malicious.\n")
    else:
        output_text.insert(tk.END, "✅ No malicious detections found.\n")
        output_text.insert(tk.END, f"{result}\n")
    output_text.config(state='disabled')

# Create main window
root = tk.Tk()
root.title("Phishing URL Detector")
root.geometry("700x400")
root.config(bg="#1e1e2f")  # dark blue background

# Fonts
title_font = font.Font(family="Helvetica", size=16, weight="bold")
label_font = font.Font(family="Arial", size=12)
button_font = font.Font(family="Arial", size=12, weight="bold")
text_font = font.Font(family="Consolas", size=11)

# Title Label
title_label = tk.Label(root, text="Phishing URL Detector", bg="#1e1e2f", fg="#ffcc00", font=title_font)
title_label.pack(pady=(15,10))

# URL input label and entry
url_label = tk.Label(root, text="Enter URL:", bg="#1e1e2f", fg="white", font=label_font)
url_label.pack(pady=(0,5))

url_entry = tk.Entry(root, width=60, font=label_font, bd=3, relief="groove")
url_entry.pack(pady=(0,15))

# Analyze button
analyze_button = tk.Button(root, text="Analyze URL", command=analyze_url_gui,
                           bg="#ffcc00", fg="#1e1e2f", font=button_font,
                           activebackground="#e6b800", activeforeground="#000000", bd=0, padx=15, pady=7)
analyze_button.pack(pady=(0,15))

# Output text box with scroll
output_text = scrolledtext.ScrolledText(root, width=80, height=10, font=text_font,
                                        bg="#2e2e3e", fg="white", bd=2, relief="sunken")
output_text.pack(padx=15, pady=(0,15))
output_text.config(state='disabled')

root.mainloop()
