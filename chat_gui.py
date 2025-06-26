import tkinter as tk
from tkinter import filedialog, END, Text, Scrollbar, Entry, Button

# GUI
window = tk.Tk()
window.title("Chatbot")

BG_GRAY = "#ABB2B9"
BG_COLOR = "#17202A"
TEXT_COLOR = "#EAECEE"

FONT = "Helvetica 30"
FONT_BOLD = "Helvetica 20 bold"

#TODO
#From: https://pythonguides.com/upload-a-file-in-python-tkinter/
def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as f:
            content = f.read()
            print(f"File content\n: {content}")

# Send function
def send():
    send = "You -> " + e.get()
    txt.insert(END, "\n" + send)
    # receive = socket.recv(1024)
    # txt.insert(END, "\n" + receive) #client response

    e.delete(0, END)

#make it dynamic
txt = Text(window, bg=BG_COLOR, fg=TEXT_COLOR, font=FONT, width=120, height=60)
txt.grid(row=1, column=0, columnspan=4)

scrollbar = Scrollbar(txt)
scrollbar.place(relheight=1, relx=0.974)

e = Entry(window, bg="#2C3E50", fg=TEXT_COLOR, font=FONT, width=55)
e.grid(row=2, column=0)

send = Button(window, text="Send", font=FONT_BOLD, bg=BG_GRAY,
              command=send).grid(row=2, column=1)

attach = Button(window, text="Upload", font=FONT_BOLD, bg=BG_GRAY,
                command=upload_file).grid(row=2, column=2)

window.mainloop()