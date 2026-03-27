import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import os


LOG_FILE = "log.txt"


DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".scr", ".js", ".msi", ".dll"
]

SUSPICIOUS_WORDS = [
    "hack", "crack", "keygen", "virus", "trojan", "patch",
    "loader", "stealer", "malware", "inject", "spoof"
]


def write_log(file_name, result_text, risk_score):
    now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    line = f"{now} | Файл: {file_name} | Результат: {result_text} | Баллы риска: {risk_score}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(line)


def analyze_file_name(file_name):
    name = file_name.strip()
    lower_name = name.lower()

    risk_score = 0
    reasons = []

    if not name:
        return None, None, None

    # Проверка на двойное расширение, например photo.jpg.exe
    parts = lower_name.split(".")
    if len(parts) >= 3:
        risk_score += 3
        reasons.append("обнаружено двойное расширение файла")

    # Проверка расширения
    file_extension = os.path.splitext(lower_name)[1]
    if file_extension in DANGEROUS_EXTENSIONS:
        risk_score += 4
        reasons.append(f"опасное расширение {file_extension}")

    # Проверка подозрительных слов
    for word in SUSPICIOUS_WORDS:
        if word in lower_name:
            risk_score += 2
            reasons.append(f"подозрительное слово: {word}")

    # Проверка количества цифр
    digit_count = sum(char.isdigit() for char in name)
    if digit_count >= 5:
        risk_score += 1
        reasons.append("слишком много цифр в названии")

    # Проверка количества специальных символов
    special_count = 0
    allowed_symbols = "._-\\/:"
    for char in name:
        if not char.isalnum() and char not in allowed_symbols:
            special_count += 1

    if special_count >= 3:
        risk_score += 2
        reasons.append("много специальных символов в названии")

    # Проверка на очень длинное имя
    if len(name) > 40:
        risk_score += 1
        reasons.append("слишком длинное имя файла")

    # Определение уровня риска
    if risk_score <= 2:
        result_text = "Безопасно"
        recommendation = "Явных опасных признаков не обнаружено."
    elif risk_score <= 5:
        result_text = "Подозрительно"
        recommendation = "Файл стоит проверить внимательнее перед открытием."
    else:
        result_text = "Опасно"
        recommendation = "Файл выглядит потенциально опасным. Не рекомендуется открывать его."

    return result_text, recommendation, reasons, risk_score


def check_file():
    file_name = entry_file.get()

    if not file_name.strip():
        messagebox.showwarning("Ошибка", "Введите имя файла или путь к файлу.")
        return

    result = analyze_file_name(file_name)

    if result[0] is None:
        messagebox.showwarning("Ошибка", "Введите корректное имя файла.")
        return

    result_text, recommendation, reasons, risk_score = result

    output_text = f"Результат анализа: {result_text}\n"
    output_text += f"Баллы риска: {risk_score}\n\n"

    if reasons:
        output_text += "Причины:\n"
        for reason in reasons:
            output_text += f"- {reason}\n"
    else:
        output_text += "Подозрительных признаков не найдено.\n"

    output_text += f"\nРекомендация:\n{recommendation}"

    label_result.config(text=output_text, justify="left")

    write_log(file_name, result_text, risk_score)


def clear_fields():
    entry_file.delete(0, tk.END)
    label_result.config(text="Здесь появится результат проверки.")


def show_history():
    history_window = tk.Toplevel(root)
    history_window.title("История проверок")
    history_window.geometry("700x400")
    history_window.resizable(False, False)

    text_area = scrolledtext.ScrolledText(history_window, wrap=tk.WORD, font=("Arial", 11))
    text_area.pack(fill="both", expand=True, padx=10, pady=10)

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            content = file.read()
            if content.strip():
                text_area.insert(tk.END, content)
            else:
                text_area.insert(tk.END, "История пока пуста.")
    else:
        text_area.insert(tk.END, "Файл истории ещё не создан.")

    text_area.config(state="disabled")


def show_about():
    about_window = tk.Toplevel(root)
    about_window.title("О программе")
    about_window.geometry("500x300")
    about_window.resizable(False, False)

    about_text = (
        "Программа анализа подозрительных файлов\n\n"
        "Назначение:\n"
        "Приложение выполняет первичную проверку имени файла и "
        "определяет уровень риска по простым признакам.\n\n"
        "Проверяются:\n"
        "- расширение файла\n"
        "- подозрительные слова\n"
        "- двойное расширение\n"
        "- количество цифр\n"
        "- специальные символы\n\n"
        "Все результаты сохраняются в файл log.txt"
    )

    label_about = tk.Label(
        about_window,
        text=about_text,
        font=("Arial", 11),
        justify="left",
        wraplength=460
    )
    label_about.pack(padx=20, pady=20)


root = tk.Tk()
root.title("Анализ подозрительных файлов")
root.geometry("750x500")
root.resizable(False, False)

label_title = tk.Label(
    root,
    text="Программа анализа подозрительных файлов",
    font=("Arial", 16, "bold")
)
label_title.pack(pady=15)

frame_input = tk.Frame(root)
frame_input.pack(pady=10)

label_file = tk.Label(
    frame_input,
    text="Введите имя файла или путь:",
    font=("Arial", 12)
)
label_file.grid(row=0, column=0, padx=5, pady=5)

entry_file = tk.Entry(frame_input, width=50, font=("Arial", 12))
entry_file.grid(row=0, column=1, padx=5, pady=5)

frame_buttons = tk.Frame(root)
frame_buttons.pack(pady=15)

button_check = tk.Button(
    frame_buttons,
    text="Проверить",
    font=("Arial", 12),
    width=15,
    command=check_file
)
button_check.grid(row=0, column=0, padx=8, pady=8)

button_clear = tk.Button(
    frame_buttons,
    text="Очистить",
    font=("Arial", 12),
    width=15,
    command=clear_fields
)
button_clear.grid(row=0, column=1, padx=8, pady=8)

button_history = tk.Button(
    frame_buttons,
    text="История",
    font=("Arial", 12),
    width=15,
    command=show_history
)
button_history.grid(row=0, column=2, padx=8, pady=8)

button_about = tk.Button(
    frame_buttons,
    text="О программе",
    font=("Arial", 12),
    width=15,
    command=show_about
)
button_about.grid(row=0, column=3, padx=8, pady=8)

label_result = tk.Label(
    root,
    text="Здесь появится результат проверки.",
    font=("Arial", 12),
    justify="left",
    anchor="nw",
    bd=1,
    relief="solid",
    width=75,
    height=15,
    padx=10,
    pady=10,
    wraplength=680
)
label_result.pack(padx=20, pady=20)

root.mainloop()
