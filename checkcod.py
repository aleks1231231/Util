import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import ast
import os
import re
import subprocess
import sys
from threading import Thread
from queue import Queue
import configparser
import difflib

# Словарь с описаниями правил pylint
PYLINT_RULES = {
    "C0111": "Отсутствует docstring",
    "C0301": "Слишком длинная строка",
    "W0611": "Неиспользуемый импорт",
    # ... другие правила
}

class CodeAnalyzer:
    def __init__(self, config):
        self.errors = []
        self.warnings = []
        self.config = config
        self.progress = 0

    def analyze_file(self, file_path, queue=None):
        """
        Анализирует файл Python на наличие ошибок и предупреждений.

        Args:
            file_path (str): Путь к файлу Python.
            queue (Queue, optional): Очередь для асинхронной обработки.
        """
        self.errors.clear()
        self.warnings.clear()
        self.progress = 0

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
        except FileNotFoundError:
            self.errors.append(("Критический", f"Ошибка: Файл не найден: '{file_path}'", 0))
            if queue:
                queue.put((self.errors, self.warnings, self.progress))
            return
        except PermissionError:
            self.errors.append(("Критический", f"Ошибка: Нет прав для доступа к файлу: '{file_path}'", 0))
            if queue:
                queue.put((self.errors, self.warnings, self.progress))
            return
        except Exception as e:
            self.errors.append(("Критический", f"Ошибка при открытии файла: {str(e)}", 0))
            if queue:
                queue.put((self.errors, self.warnings, self.progress))
            return

        try:
            tree = ast.parse(content, file_path)
            self.progress = 20  # Обновляем прогресс после парсинга AST

            # Дополнительные проверки с помощью ast
            if self.config.getboolean('checks', 'print_in_functions'):
                self._check_print_in_functions(tree)
            if self.config.getboolean('checks', 'input_in_functions'):
                self._check_input_in_functions(tree)
            if self.config.getboolean('checks', 'global_variables'):
                self._check_global_variables(tree)
            if self.config.getboolean('checks', 'try_except_without_else'):
                self._check_try_except_without_else(tree)
            if self.config.getboolean('checks', 'while_true'):
                self._check_while_true(tree)
            if self.config.getboolean('checks', 'duplicate_code'):
                self._check_duplicate_code(content)
            self.progress = 40  # Обновляем прогресс после проверок AST

            # Вычисляем цикломатическую сложность для каждой функции
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    complexity = self._calculate_cyclomatic_complexity(node)
                    message = f"Функция '{node.name}' имеет цикломатическую сложность {complexity}"
                    severity = self.config.get('severity', 'cyclomatic_complexity', fallback='Незначительный')
                    self.warnings.append((severity, message, node.lineno))

            # Интеграция внешних инструментов
            self.run_external_tools(file_path)
            self.progress = 100  # Обновляем прогресс после внешних инструментов

        except SyntaxError as e:
            self.errors.append(("Критический", f"Синтаксическая ошибка: {str(e)}", e.lineno))
            if queue:
                queue.put((self.errors, self.warnings, self.progress))
            return

        if queue:
            queue.put((self.errors, self.warnings, self.progress))

    def _check_print_in_functions(self, tree):
        """
        Проверяет, используются ли `print` в функциях.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name) and subnode.func.id == 'print':
                        line_number = subnode.lineno
                        message = f"Использование `print` в функции '{node.name}' (строка {line_number}) может быть нежелательным."
                        severity = self.config.get('severity', 'print_in_functions', fallback='Незначительный')
                        self.warnings.append((severity, message, line_number))

    def _check_input_in_functions(self, tree):
        """
        Проверяет, используются ли `input` в функциях.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name) and subnode.func.id == 'input':
                        line_number = subnode.lineno
                        message = f"Использование `input` в функции '{node.name}' (строка {line_number}) может быть нежелательным."
                        severity = self.config.get('severity', 'input_in_functions', fallback='Незначительный')
                        self.warnings.append((severity, message, line_number))

    def _check_global_variables(self, tree):
        """
        Проверяет, используются ли глобальные переменные в функциях.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Name) and isinstance(subnode.ctx, ast.Load):
                        if subnode.id in [name.id if isinstance(name, ast.Name) else name.asname for name in tree.body[0].names]:
                            line_number = subnode.lineno
                            message = f"Использование глобальной переменной '{subnode.id}' в функции '{node.name}' (строка {line_number})."
                            severity = self.config.get('severity', 'global_variables', fallback='Незначительный')
                            self.warnings.append((severity, message, line_number))

    def _check_try_except_without_else(self, tree):
        """
        Проверяет, есть ли `try...except` блоки без `else` ветки.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                if not any(isinstance(handler, ast.Try) for handler in node.handlers):
                    line_number = node.lineno
                    message = f"`try...except` блок без `else` ветки (строка {line_number})."
                    severity = self.config.get('severity', 'try_except_without_else', fallback='Незначительный')
                    self.warnings.append((severity, message, line_number))

    def _check_while_true(self, tree):
        """
        Проверяет, используются ли `while True` без явного условия выхода из цикла.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and node.test.value is True:
                line_number = node.lineno
                message = f"Использование `while True` без явного условия выхода из цикла (строка {line_number})."
                severity = self.config.get('severity', 'while_true', fallback='Незначительный')
                self.warnings.append((severity, message, line_number))

    def _check_duplicate_code(self, content):
        """
        Проверяет наличие дублирования кода.
        """
        lines = content.splitlines()
        for i in range(len(lines) - 6):  # Проверяем блоки кода по 6 строк
            block1 = lines[i:i+6]
            for j in range(i+6, len(lines) - 6):
                block2 = lines[j:j+6]
                if block1 and block2 and difflib.SequenceMatcher(None, block1, block2).ratio() > 0.8:
                    message = f"Обнаружено дублирование кода (строки {i+1}-{i+6} и {j+1}-{j+6})."
                    severity = self.config.get('severity', 'duplicate_code', fallback='Незначительный')
                    self.warnings.append((severity, message, i+1))

    def _calculate_cyclomatic_complexity(self, function_node):
        """
        Вычисляет цикломатическую сложность функции.
        """
        complexity = 1
        for node in ast.walk(function_node):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
                complexity += len(node.values) - 1
        return complexity

    def run_external_tools(self, file_path):
        """
        Запускает внешние инструменты анализа кода.
        """
        tools = ['flake8', 'mypy', 'pylint', 'pycodestyle', 'pyflakes', 'bandit']
        for tool in tools:
            if self.config.getboolean('tools', tool):
                try:
                    getattr(self, f'_run_{tool}')(file_path)
                except FileNotFoundError as e:
                    self.warnings.append(("Серьёзный", f"Ошибка: Внешний инструмент анализа кода '{e.filename}' не найден. Установите его с помощью 'pip install {e.filename}'. ", 0))
                except Exception as e:
                    self.errors.append(("Критический", f"Ошибка при запуске {tool}: {str(e)}", 0))

    def _run_flake8(self, file_path):
        """
        Запускает flake8 для проверки стиля кода.
        """
        result = subprocess.run([sys.executable, '-m', 'flake8', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            for line in result.stdout.splitlines():
                try:
                    line_number = int(line.split(":")[1])
                except:
                    line_number = 0
                self.warnings.append(('Незначительный', line, line_number))

    def _run_mypy(self, file_path):
        """
        Запускает mypy для проверки типизации кода.
        """
        result = subprocess.run([sys.executable, '-m', 'mypy', '--ignore-missing-imports', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            for line in result.stdout.splitlines():
                try:
                    line_number = int(line.split(":")[1])
                except:
                    line_number = 0
                self.warnings.append(('Незначительный', line, line_number))

    def _run_pylint(self, file_path):
        """
        Запускает pylint для проверки кода.
        """
        result = subprocess.run([sys.executable, '-m', 'pylint', '--output-format=parseable', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            for line in result.stdout.splitlines():
                match = re.match(r"(.+):(\d+): \[(\w+), (.+)\] (.+)", line)
                if match:
                    file, line_no, code, symbol, message = match.groups()
                    rule_description = PYLINT_RULES.get(code, "")
                    full_message = f"Файл '{file}', строка {line_no}: [{code}, {symbol}] {message} - {rule_description}"
                    severity = self.config.get('severity', code, fallback='Незначительный')
                    self.warnings.append((severity, full_message, int(line_no)))

    def _run_pycodestyle(self, file_path):
        """
        Запускает pycodestyle для проверки стиля кода.
        """
        result = subprocess.run([sys.executable, '-m', 'pycodestyle', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            for line in result.stdout.splitlines():
                try:
                    line_number = int(line.split(":")[1])
                except:
                    line_number = 0
                self.warnings.append(('Незначительный', line, line_number))

    def _run_pyflakes(self, file_path):
        """
        Запускает pyflakes для проверки кода.
        """
        result = subprocess.run([sys.executable, '-m', 'pyflakes', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            for line in result.stdout.splitlines():
                try:
                    line_number = int(line.split(":")[1])
                except:
                    line_number = 0
                self.warnings.append(('Незначительный', line, line_number))

    def _run_bandit(self, file_path):
        """
        Запускает bandit для проверки кода на уязвимости безопасности.
        """
        result = subprocess.run([sys.executable, '-m', 'bandit', '-r', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            for line in result.stdout.splitlines():
                try:
                    line_number = int(line.split(":")[1])
                except:
                    line_number = 0
                self.warnings.append(('Серьёзный', line, line_number))

class Application(tk.Frame):
    def __init__(self, master=None, config=None):
        super().__init__(master)
        self.master = master
        self.master.title("Python Code Analyzer")
        self.master.geometry("800x600")
        self.pack(fill=tk.BOTH, expand=True)
        self.config = config
        self.create_widgets()

    def create_widgets(self):
        self.select_button = tk.Button(self, text="Выбрать Python файл", command=self.select_file)
        self.select_button.pack(pady=20)

        self.result_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=90, height=25)
        self.result_text.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        self.result_text.tag_config('link', foreground="blue", underline=True)
        self.result_text.bind("<Button-1>", self.handle_click)

        self.progress_label = tk.Label(self, text="Анализ...")
        self.progress_label.pack(side="bottom", pady=10)

        self.quit = tk.Button(self, text="Выход", fg="red", command=self.master.destroy)
        self.quit.pack(side="bottom", pady=20)

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
        if file_path:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, "Анализ файла...\n", 'info')
            self.result_text.tag_config('info', foreground='blue')
            self.result_text.update()

            self.progress_label.config(text="Анализ: 0%")
            self.progress_label.pack(side="bottom", pady=10)

            queue = Queue()
            analyzer = CodeAnalyzer(self.config)
            analysis_thread = Thread(target=analyzer.analyze_file, args=(file_path, queue))
            analysis_thread.start()

            def check_results():
                if analysis_thread.is_alive():
                    self.progress_label.config(text=f"Анализ: {analyzer.progress}%")
                    self.after(100, check_results)
                else:
                    errors, warnings, _ = queue.get()
                    self.display_results(errors, warnings, file_path)
                    self.progress_label.config(text="Анализ завершен.")

            check_results()

    def display_results(self, errors, warnings, file_path):
        self.result_text.delete('1.0', tk.END)
        self.file_path = file_path
        if errors or warnings:
            self.result_text.insert(tk.END, "----- Ошибки & Предупреждения -----\n")
            for severity, message, line_number in errors + warnings:
                if severity == "Критический":
                    tag = 'critical'
                elif severity == "Серьёзный":
                    tag = 'error'
                else:
                    tag = 'warning'
                self.result_text.insert(tk.END, f"{severity}: {message} (строка {line_number})\n", (tag, f'link-{line_number}'))
        else:
            self.result_text.insert(tk.END, "Ошибок и предупреждений не найдено.")
        self.result_text.tag_config('critical', foreground='red', font=('bold', 10))
        self.result_text.tag_config('error', foreground='red')
        self.result_text.tag_config('warning', foreground='orange')

    def handle_click(self, event):
        try:
            line_number = int(self.result_text.tag_names(tk.CURRENT)[1].split('-')[1])
            self.open_file_at_line(self.file_path, line_number)
        except:
            pass

    def open_file_at_line(self, file_path, line_number):
        try:
            if sys.platform.startswith('win'):
                subprocess.run(['start', file_path, f'/e:{line_number}'], shell=True)
            elif sys.platform.startswith('linux'):
                subprocess.run(['gedit', f'+{line_number}', file_path])
            elif sys.platform.startswith('darwin'):
                subprocess.run(['open', '-e', file_path, f'--args', f'+{line_number}'])
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть файл: {str(e)}")

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('analyzer.ini')  # Читаем настройки из файла

    root = tk.Tk()
    app = Application(master=root, config=config)
    app.mainloop()