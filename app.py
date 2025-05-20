import os
import threading
from tkinter import filedialog
from androguard.misc import AnalyzeAPK
import tkinter as tk
from PIL import Image, ImageTk
from tkinter import ttk, messagebox
from CyberSleuth import CyberSleuth  # Make sure you have this module implemented
from gtts import gTTS
import pygame
import tempfile
import time
import random

# Initialize pygame mixer
pygame.mixer.init()

def speak(text):
    """
    Uses gTTS and pygame to convert text to speech with temporary file playback.
    Falls back gracefully if gTTS or audio playback fails.
    """
    try:
        tts = gTTS(text=text, lang='en')
        temp_path = tempfile.NamedTemporaryFile(delete=False, suffix=".mp3").name
        tts.save(temp_path)

        try:
            sound = pygame.mixer.Sound(temp_path)
            sound.play()

            while pygame.mixer.get_busy():
                pygame.time.Clock().tick(10)

        except Exception as audio_error:
            print(f"[!] Audio playback error: {audio_error}")

        finally:
            try:
                os.remove(temp_path)
            except PermissionError:
                time.sleep(0.5)
                try:
                    os.remove(temp_path)
                except Exception as delete_error:
                    print(f"[!] Could not delete temp file: {delete_error}")

    except Exception as gtts_error:
        print(f"[!] Text-to-speech failed: {gtts_error}")


def typing_animation(widget, text, color="lime", delay=0.004):
    widget.tag_config(color, foreground=color)
    for char in text:
        widget.insert(tk.END, char, color)
        widget.see(tk.END)
        widget.update_idletasks()
        time.sleep(delay)

def get_random_color():
    colors = ["cyan", "orange", "magenta", "lime", "yellow", "red"]
    return random.choice(colors)

def fake_loading_bar():
    loading_colors = ["cyan", "yellow", "lime", "magenta"]
    for i in range(1, 35):
        typing_animation(result_text, "█", random.choice(loading_colors), delay=0.02)
    typing_animation(result_text, "\n[✔️] Loading Complete.\n", "green", delay=0.01)

def scan_and_display(url):
    try:
        sleuth = CyberSleuth(url)
        speak("JARVIS online. Initiating scan.")
        typing_animation(result_text, "\n=============================", "magenta", 0.002)
        typing_animation(result_text, "\n👽 CYBER SLEUTH — JARVIS INTERFACE", "magenta", 0.003)
        typing_animation(result_text, "\n🔧 Built by: The Cyber Clubers ⚙️", "cyan", 0.003)
        typing_animation(result_text, "\n=============================\n\n", "magenta", 0.002)

        typing_animation(result_text, f"\n🔍 Initializing advanced scan for: {url}\n", "cyan", delay=0.005)

        # JARVIS-style intro
        typing_animation(result_text, "\n🤖 JARVIS Activated...\n", "magenta", delay=0.01)
        typing_animation(result_text, "\n🔬 Analyzing the website using multiple intelligent agents...\n", "cyan", delay=0.01)
        typing_animation(result_text, "\n📡 Checking for vulnerabilities, phishing indicators, and more.\n", "yellow", delay=0.01)
        typing_animation(result_text, "\n🧠 Pattern matching, fingerprinting technologies, and header inspection underway...\n", "orange", delay=0.01)
        typing_animation(result_text, "\n🚨 If threats are detected, JARVIS will flag them for your awareness.\n", "red", delay=0.01)
        typing_animation(result_text, "\n🔎 Starting deep scan...\n\n", "lime", delay=0.01)

        # Fake loading bar
        fake_loading_bar()

        sleuth.run_scan()

        for agent in sleuth.agents:
            agent_color = get_random_color()
            typing_animation(result_text, f"\n>> {agent.agent_name} [{agent.specialty}]\n", agent_color, delay=0.003)
            if agent.findings:
                for finding in agent.findings:
                    typing_animation(result_text, f" • {finding}\n", agent_color, delay=0.001)
            else:
                typing_animation(result_text, " • No findings.\n", agent_color, delay=0.002)

        typing_animation(result_text, "\n\n🧠 Final Verdict:\n", "yellow", delay=0.004)
        if sleuth.risk_flags > 2:
            verdict = "⚠️ ALERT: Multiple vulnerabilities found. This site could be exploited."
            speak("Warning. Vulnerabilities detected. Proceed with caution.")
            verdict_color = "red"
        else:
            verdict = "✅ No critical issues found. The website appears safe for now."
            speak("Scan complete. Website appears safe.")
            verdict_color = "green"
        typing_animation(result_text, verdict + "\n", verdict_color, delay=0.004)

        typing_animation(result_text, "\n🌐 CyberSleuth — Powered by JARVIS | The Cyber Clubers 🚀\n", "magenta", delay=0.003)

    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        scan_button.config(state='normal')
        progress.stop()

def analyze_apk(filepath):
    try:
        speak("Analyzing Android application. Please wait.")
        typing_animation(result_text, f"\n📱 Analyzing APK: {os.path.basename(filepath)}\n", "cyan", delay=0.005)

        a, d, dx = AnalyzeAPK(filepath)

        typing_animation(result_text, "\n📦 App Info:\n", "yellow")
        typing_animation(result_text, f" • Package Name: {a.get_package()}\n", "lime")
        typing_animation(result_text, f" • Main Activity: {a.get_main_activity()}\n", "lime")
        typing_animation(result_text, f" • Permissions:\n", "orange")

        permissions = a.get_permissions()
        if permissions:
            for perm in permissions:
                typing_animation(result_text, f"   - {perm}\n", "magenta", delay=0.001)
        else:
            typing_animation(result_text, "   - No permissions found.\n", "magenta")

        typing_animation(result_text, f"\n🔍 Activities: {len(a.get_activities())}", "cyan")
        typing_animation(result_text, f"\n🔐 Services: {len(a.get_services())}", "cyan")
        typing_animation(result_text, f"\n📡 Receivers: {len(a.get_receivers())}\n", "cyan")

        # Basic threat check
        suspicious = [perm for perm in permissions if "SMS" in perm or "CALL" in perm or "RECEIVE_BOOT_COMPLETED" in perm]
        if suspicious:
            typing_animation(result_text, "\n🚨 Suspicious Permissions Detected:\n", "red")
            for s in suspicious:
                typing_animation(result_text, f"   ⚠️ {s}\n", "red")
            speak("Warning. The app uses sensitive permissions.")
        else:
            typing_animation(result_text, "\n✅ No suspicious permissions detected.\n", "green")
            speak("App analysis complete. No immediate threats found.")

        typing_animation(result_text, "\n📱 App Analysis Complete — Powered by JARVIS\n", "magenta")

    except Exception as e:
        messagebox.showerror("APK Analysis Error", str(e))
    finally:
        scan_button.config(state='normal')
        progress.stop()


def run_scan():
    url = url_entry.get().strip()
    if not url.startswith("http"):
        messagebox.showerror("Invalid URL", "Please include the URL scheme (http or https).")
        return
    scan_button.config(state='disabled')
    result_text.delete("1.0", tk.END)
    progress.start(10)
    threading.Thread(target=scan_and_display, args=(url,)).start()

def select_apk():
    filepath = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
    if filepath:
        result_text.delete("1.0", tk.END)
        progress.start(10)
        scan_button.config(state='disabled')
        threading.Thread(target=analyze_apk, args=(filepath,)).start()

# GUI Setup
root = tk.Tk()
root.title("CyberSleuth JARVIS Console - The Cyber Clubers")
root.geometry("1100x750")
bg_image = Image.open("background.png")
bg_image = bg_image.resize((1100, 750), Image.Resampling.LANCZOS)
bg_photo = ImageTk.PhotoImage(bg_image)
bg_label = tk.Label(root, image=bg_photo)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)
root.configure(bg="#000000")


# Styling
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", foreground="lime", background="#111111", padding=10, font=("Courier New", 14, "bold"))
style.configure("TLabel", foreground="lime", background="#000000", font=("Courier New", 14))
style.configure("TEntry", fieldbackground="#202020", foreground="lime", font=("Courier New", 14))

# Header
header = ttk.Label(root, text="🧠 JARVIS Console - CyberSleuth AI Edition", font=("Courier New", 20, "bold"), foreground="lime")
header.pack(pady=20)

# URL Entry
url_label = ttk.Label(root, text="Enter Target Website:")
url_label.pack()
url_entry = ttk.Entry(root, width=70)
url_entry.pack(pady=5)

# Scan Button
scan_button = ttk.Button(root, text="Engage Scan Protocol ⚔️", command=run_scan)
scan_button.pack(pady=10)

# Progress Bar
progress = ttk.Progressbar(root, mode='indeterminate', length=300)
progress.pack(pady=5)

# APK Analysis Button
apk_button = ttk.Button(root, text="Analyze App APK 📱", command=select_apk)
apk_button.pack(pady=10)

# Result Text Box
result_text = tk.Text(root, wrap="word", bg="#101010", fg="lime", font=("Courier New", 13, "bold"), insertbackground="lime")
result_text.pack(expand=True, fill="both", padx=20, pady=10)

def play_background_music():
    try:
        pygame.mixer.music.load("bg_music.mp3")  # Change filename as needed
        pygame.mixer.music.set_volume(0.1)       # Set volume (0.0 to 1.0)
        pygame.mixer.music.play(-1)              # -1 = loop forever
    except Exception as e:
        print(f"[!] Error playing background music: {e}")

def on_closing():
    pygame.mixer.music.stop()
    pygame.quit()  # Cleanly shutdown pygame to avoid lingering audio
    root.destroy()

# Start GUI
play_background_music()
root.mainloop()
