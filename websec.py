import tkinter as tk
import customtkinter as ctk
import requests
import socket
import threading
import subprocess
import ipaddress
import tkintermapview
import os
import time
import math
import random
import httpx
import concurrent.futures
import hashlib
import queue
from random import choice
from functools import partial
from tkinter import ttk
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from PIL import Image
# Настройка внешнего вида
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")




class UltraSimpleScanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Основные настройки окна
        self.title("WebSec")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        self.iconbitmap("iconw.ico")

        # Создаем сетку
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        
        # Верхняя панель
        self.header_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#2c3e50")
        self.header_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        self.target_entry = ctk.CTkEntry(
            self.header_frame, 
            placeholder_text="Введите домен или IP...",
            width=400,
            height=40,
            font=("Arial", 16),
            corner_radius=8
        )
        self.target_entry.pack(side="left", padx=20, pady=15, fill="x", expand=True)
        self.target_entry.bind("<Return>", self.start_scan)
        
        self.scan_btn = ctk.CTkButton(
            self.header_frame, 
            text="Сканировать",
            command=self.start_scan,
            height=40,
            width=120,
            font=("Arial", 14, "bold"),
            fg_color="#27ae60",
            hover_color="#2ecc71",
            corner_radius=8
        )
        self.scan_btn.pack(side="right", padx=20, pady=15)
        
        self.cancel_btn = ctk.CTkButton(
            self.header_frame, 
            text="Отменить",
            command=self.cancel_scan,
            height=40,
            width=100,
            font=("Arial", 14),
            fg_color="#e74c3c",
            hover_color="#c0392b",
            corner_radius=8,
            state="disabled"
        )
        self.cancel_btn.pack(side="right", padx=(0, 10), pady=15)
        
        # Панель анимации
        self.connection_frame = ctk.CTkFrame(self, height=25, corner_radius=10, fg_color="#1a1a1a")
        self.connection_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        self.connection_frame.grid_propagate(False)
        self.grid_rowconfigure(1, weight=0, minsize=25)
        
        self.canvas = tk.Canvas(self.connection_frame, bg=self.connection_frame.cget("fg_color"), highlightthickness=0, height=35)
        self.canvas.pack(fill="both", expand=False, padx=20, pady=10)
        
        # Переменные для анимации
        self.animation_pos = 0
        self.animation_id = None
        self.my_ip = "127.0.0.1"
        self.server_ip = "0.0.0.0"
        self.hidden_ip = "***.***.***.***"
        self.reveal_progress = 0
        self.reveal_steps = 15
        self.bit_particles = []
        self.animation_complete = False
        self.animation_running = False
        self.last_frame_time = 0
        self.frame_duration = 1/30  # 30 FPS вместо 60
        
        # Левая панель
        self.info_frame = ctk.CTkFrame(self, corner_radius=10)
        self.info_frame.grid(row=2, column=0, padx=(20, 10), pady=(0, 20), sticky="nsew")
        self.info_frame.grid_rowconfigure(0, weight=1)
        self.info_frame.grid_columnconfigure(0, weight=1)
        
        # Правая панель
        self.map_frame = ctk.CTkFrame(self, corner_radius=10)
        self.map_frame.grid(row=2, column=1, padx=(10, 20), pady=(0, 20), sticky="nsew")
        self.map_frame.grid_rowconfigure(0, weight=1)
        self.map_frame.grid_columnconfigure(0, weight=1)
        
        # Карта
        self.map_widget = tkintermapview.TkinterMapView(
            self.map_frame, 
            corner_radius=8
        )
        self.map_widget.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.map_widget.set_position(55.7558, 37.6173)
        self.map_widget.set_zoom(3)
        
        # Контейнер для информации
        self.tabview = ctk.CTkTabview(self.info_frame, corner_radius=8)
        self.tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.tabview.grid_columnconfigure(0, weight=1)

        # Вкладки
        self.tab_geo = self.tabview.add("Геолокация и порты")
        self.tab_paths = self.tabview.add("Веб-пути")
        self.tab_subdomains = self.tabview.add("Поддомены")

        self.tabview.set("Геолокация и порты")

        # Вкладка геолокации
        self.tab_geo.grid_columnconfigure(0, weight=1)
        self.tab_geo.grid_rowconfigure(0, weight=0)
        self.tab_geo.grid_rowconfigure(1, weight=1)

        geo_frame = ctk.CTkFrame(self.tab_geo, corner_radius=8)
        geo_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ctk.CTkLabel(
            geo_frame, 
            text="Геолокация",
            font=("Arial", 14, "bold"),
            anchor="w"
        ).pack(fill="x", padx=10, pady=(10, 5))

        self.geo_text = ctk.CTkTextbox(
            geo_frame, 
            height=150,
            wrap="word",
            font=("Arial", 13),
            activate_scrollbars=False
        )
        self.geo_text.pack(fill="x", padx=10, pady=(0, 10))
        self.geo_text.insert("1.0", "Данные геолокации появятся здесь после сканирования")
        self.geo_text.configure(state="disabled")

        # Секция портов
        ports_frame = ctk.CTkFrame(self.tab_geo, corner_radius=8)
        ports_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        ports_frame.grid_rowconfigure(0, weight=1)
        ports_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            ports_frame, 
            text="Открытые порты",
            font=("Arial", 13, "bold"),
            anchor="w"
        ).pack(fill="x", padx=10, pady=(10, 5))

        self.ports_text = ctk.CTkTextbox(
            ports_frame, 
            wrap="word",
            font=("Consolas", 14),
            activate_scrollbars=True
        )
        self.ports_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.ports_text.insert("1.0", "Результаты сканирования портов появятся здесь")
        self.ports_text.configure(state="disabled")

        # Вкладка веб-путей (ИСПРАВЛЕНО: изменен порядок колонок)
        self.tab_paths.grid_columnconfigure(0, weight=1)
        self.tab_paths.grid_rowconfigure(0, weight=0)
        self.tab_paths.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self.tab_paths, 
            text="Доступные веб-пути",
            font=("Arial", 14, "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        tree_frame = ctk.CTkFrame(self.tab_paths, corner_radius=8, fg_color="#2a2d2e")
        tree_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        # Стиль для Treeview
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("Treeview", 
                        background="#292828",
                        foreground="white",
                        rowheight=30,
                        fieldbackground="#2a2d2e",
                        font=('Arial', 12),
                        borderwidth=0,
                        highlightthickness=0,
                        relief="flat")
        
        style.configure("Treeview.Heading", 
                        background="#1e1e1e", 
                        foreground="#fff",
                        font=('Arial', 12, 'bold'),
                        padding=(5, 5),
                        relief="flat",
                        borderwidth=0)
        
        style.map("Treeview", 
                  background=[('selected', '#22559b')],
                  foreground=[('selected', 'white')])
        
        style.map("Treeview.Heading", 
                  background=[('active', '#3d3d3d')])

        # Treeview для путей (ИСПРАВЛЕНО: изменен порядок колонок)
        self.paths_tree = ttk.Treeview(
            tree_frame,
            columns=("url", "status", "type"),  # Поменяли местами status и url
            show="headings",
            selectmode="browse",
            style="Treeview"
        )
        
        # Измененный порядок колонок: URL, Статус, Тип
        self.paths_tree.heading("url", text="URL", anchor="w", command=lambda: self.sort_treeview("url", "paths"))
        self.paths_tree.heading("status", text="Статус", anchor="w", command=lambda: self.sort_treeview("status", "paths"))
        self.paths_tree.heading("type", text="Тип", anchor="w", command=lambda: self.sort_treeview("type", "paths"))
        
        self.paths_tree.column("url", width=350, minwidth=250, stretch=True)
        self.paths_tree.column("status", width=100, minwidth=90, stretch=False)
        self.paths_tree.column("type", width=100, minwidth=80, stretch=False)
        
        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient="vertical",
            command=self.paths_tree.yview
        )
        self.paths_tree.configure(yscrollcommand=scrollbar.set)
        
        self.paths_tree.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=0, pady=0)
        
        self.paths_tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        
        self.paths_context_menu = tk.Menu(self, tearoff=0)
        self.paths_context_menu.add_command(label="Копировать", command=lambda: self.copy_treeview_data(self.paths_tree))
        self.paths_tree.bind("<Button-3>", self.show_context_menu)
        
        # Вкладка поддоменов
        self.tab_subdomains.grid_columnconfigure(0, weight=1)
        self.tab_subdomains.grid_rowconfigure(0, weight=0)
        self.tab_subdomains.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self.tab_subdomains, 
            text="Найденные поддомены",
            font=("Arial", 14, "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        subdomains_frame = ctk.CTkFrame(self.tab_subdomains, corner_radius=8, fg_color="#2a2d2e")
        subdomains_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        subdomains_frame.grid_columnconfigure(0, weight=1)
        subdomains_frame.grid_rowconfigure(0, weight=1)

        # Treeview для поддоменов
        self.subdomains_tree = ttk.Treeview(
            subdomains_frame,
            columns=("subdomain", "ip", "status", "length"),
            show="headings",
            selectmode="browse",
            style="Treeview"
        )
        
        self.subdomains_tree.heading("subdomain", text="Поддомен", anchor="w", command=lambda: self.sort_treeview("subdomain", "subdomains"))
        self.subdomains_tree.heading("ip", text="IP-адрес", anchor="w", command=lambda: self.sort_treeview("ip", "subdomains"))
        self.subdomains_tree.heading("status", text="Статус", anchor="w", command=lambda: self.sort_treeview("status", "subdomains"))
        self.subdomains_tree.heading("length", text="Длина", anchor="w", command=lambda: self.sort_treeview("length", "subdomains"))
        
        self.subdomains_tree.column("subdomain", width=180, minwidth=150, stretch=True)
        self.subdomains_tree.column("ip", width=140, minwidth=120, stretch=False)
        self.subdomains_tree.column("status", width=70, minwidth=60, stretch=False)
        self.subdomains_tree.column("length", width=80, minwidth=70, stretch=False)
        
        subdomains_scrollbar = ttk.Scrollbar(
            subdomains_frame,
            orient="vertical",
            command=self.subdomains_tree.yview
        )
        self.subdomains_tree.configure(yscrollcommand=subdomains_scrollbar.set)
        
        self.subdomains_tree.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        subdomains_scrollbar.grid(row=0, column=1, sticky="ns", padx=0, pady=0)
        
        self.subdomains_context_menu = tk.Menu(self, tearoff=0)
        self.subdomains_context_menu.add_command(label="Копировать", command=lambda: self.copy_treeview_data(self.subdomains_tree))
        self.subdomains_tree.bind("<Button-3>", self.show_context_menu)
        
        # Переменные для сортировки
        self.sort_column = {
            "paths": "url",
            "subdomains": "subdomain"
        }
        self.sort_direction = {
            "paths": "asc",
            "subdomains": "asc"
        }
        
        # Статус бар




        self.status_frame = ctk.CTkFrame(self, fg_color="#333333", corner_radius=0)
        self.status_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar(value="Готов к сканированию")
        self.status_bar = ctk.CTkLabel(
            self.status_frame, 
            textvariable=self.status_var,
            anchor="w",
            font=("Arial", 12),
            fg_color="transparent",
            corner_radius=0,
            padx=20
        )
        self.status_bar.grid(row=0, column=0, sticky="ew")
        
        # Кнопка информации (стилизованная под часть статус-бара)
        self.info_btn = ctk.CTkButton(
            self.status_frame,
            text="ℹ",
            width=30,
            height=30,
            font=("Arial", 14, "bold"),
            fg_color="transparent",
            hover_color="#555555",
            text_color="#ffffff",
            command=self.show_info,
            corner_radius=0
        )
        self.info_btn.grid(row=0, column=1, padx=(0, 10), sticky="e")
        
        # Переменные
        self.scan_active = False
        self.scan_cancel = False
        self.marker = None
        self.scan_thread = None
        self.paths_data = []
        self.subdomains_data = []
        
        # Очередь для результатов
        self.subdomain_queue = queue.Queue()
        self.path_queue = queue.Queue()
        
        # Таймер для обновления GUI
        self.gui_update_id = None
        self.GUI_UPDATE_INTERVAL = 1000  # Обновление раз в секунду
        
        # Буферы для накопления результатов
        self.paths_buffer = []
        self.subdomains_buffer = []
        
        # Время последнего обновления
        self.last_paths_update = 0
        self.last_subdomains_update = 0
        
        # Определяем наш IP
        self.get_my_ip()
        
        # Запускаем обработчик очередей
        self.after(100, self.process_queues)
        
        # Статические элементы анимации
        self.static_items = []
        self.particle_items = []
    def show_info(self):
        """Показывает информационное окно о программе"""
        info_window = ctk.CTkToplevel(self)
        info_window.title("О программе WebSec")
        info_window.geometry("650x500")
        info_window.resizable(False, False)





        info_window.transient(self)  # Устанавливаем родительское окно
        info_window.grab_set()  # Захватываем фокус
        info_window.lift()  # Поднимаем окно поверх всех
        info_window.focus_force()  # Принудительно устанавливаем фокус
        
        # Основной фрейм
        main_frame = ctk.CTkFrame(info_window, corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Фрейм для верхней части (картинка + заголовок)
        top_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        # Загружаем и размещаем картинку с прозрачностью
        try:
            # Используем PIL для загрузки изображения с альфа-каналом
            from PIL import Image
            pil_image = Image.open("logo.png").convert("RGBA")
            
            # Создаем CTkImage с прозрачностью
            logo_img = ctk.CTkImage(
                light_image=pil_image,
                dark_image=pil_image,  # Используем то же изображение для темной темы
                size=(100, 100)
            )
            
            # Создаем CTkLabel с прозрачным фоном
            img_label = ctk.CTkLabel(
                top_frame, 
                image=logo_img,
                text="",  # Пустой текст
                fg_color="transparent"  # Прозрачный фон
            )
            img_label.pack(side="left", padx=(0, 20))
            
        except Exception as e:
            print(f"Не удалось загрузить изображение: {e}")
            # Заглушка если картинка не загрузилась
            img_label = ctk.CTkLabel(
                top_frame, 
                text="🌐", 
                font=("Arial", 50),
                fg_color="transparent"
            )
            img_label.pack(side="left", padx=(0, 20))
        
        # Заголовок рядом с картинкой
        title_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        title_frame.pack(side="left", fill="both", expand=True)
        
        title_label = ctk.CTkLabel(
            title_frame,
            text="WebSec",
            font=("Arial", 24, "bold"),
            anchor="w"
        )
        title_label.pack(pady=(10, 0))
        
        subtitle_label = ctk.CTkLabel(
            title_frame,
            text="Сканер безопасности веб-ресурсов",
            font=("Arial", 16),
            anchor="w"
        )
        subtitle_label.pack()
        
        # Разделительная линия
        ctk.CTkFrame(
            main_frame, 
            height=2, 
            fg_color="#333333"
        ).pack(fill="x", padx=20, pady=10)
        
        # Информация о программе
        info_text = """
    WebSec - это мощный инструмент для анализа безопасности веб-ресурсов, 
    который позволяет:
        
    • Определять геолокацию сервера
    • Сканировать открытые порты
    • Находить доступные поддомены
    • Проверять доступные веб-пути
        
    Программа использует открытые API для определения геолокации
    и многопоточное сканирование для ускорения проверок.
        
    Версия: 0.3
    Разработчик: Scadane
    """
        info_label = ctk.CTkLabel(
            main_frame,
            text=info_text,
            font=("Arial", 14),
            justify="left",
            anchor="w"
        )
        info_label.pack(fill="x", padx=20, pady=10)
        
        # Ссылка на GitHub
        github_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        github_frame.pack(fill="x", padx=20, pady=(10, 15))
        
        ctk.CTkLabel(
            github_frame,
            text="GitHub:",
            font=("Arial", 14, "bold"),
            anchor="w"
        ).pack(side="left", padx=(0, 10))
        
        github_link = ctk.CTkLabel(
            github_frame,
            text="https://github.com/Scadane/WebSec",
            font=("Arial", 14, "underline"),
            text_color="#3498db",
            cursor="hand2",
            anchor="w"
        )
        github_link.pack(side="left", fill="x", expand=True)
        github_link.bind("<Button-1>", lambda e: self.open_github())
        
        # Кнопка закрытия
        close_btn = ctk.CTkButton(
            main_frame,
            text="Закрыть",
            command=info_window.destroy,
            width=120,
            height=35,
            font=("Arial", 14),
            fg_color="#2c3e50",
            hover_color="#34495e"
        )
        close_btn.pack(pady=(10, 15))
    def setup_animation(self):
        """Создаем статичные элементы анимации"""
        self.canvas.delete("all")
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        if width < 100 or height < 20:
            return
            
        # Рисуем линию подключения
        line = self.canvas.create_line(50, height//2, width-50, height//2, fill="#333", width=2, dash=(4, 2))
        self.static_items.append(line)
        
        # Рисуем точки подключения
        dot1 = self.canvas.create_oval(45, height//2-3, 55, height//2+3, fill="#3498db", outline="")
        dot2 = self.canvas.create_oval(width-55, height//2-3, width-45, height//2+3, fill="#e74c3c", outline="")
        self.static_items.extend([dot1, dot2])
        
        # Создаем текст для IP
        self.my_ip_text = self.canvas.create_text(10, height//2-10, text=f"{self.my_ip}", 
                              anchor="w", fill="#3498db", font=("Arial", 12))
        self.server_ip_text = self.canvas.create_text(width-10, height//2-10, text=f"{self.hidden_ip}", 
                              anchor="e", fill="#e74c3c", font=("Arial", 12))
        self.static_items.extend([self.my_ip_text, self.server_ip_text])
        
        # Текст статуса
        self.status_text = self.canvas.create_text(width//2, height//2+10, text="", 
                                  fill="#2ecc71", font=("Arial", 10, "bold"))
        self.static_items.append(self.status_text)
        
    def process_queues(self):
        """Обработка очередей результатов"""
        # Обрабатываем поддомены
        subdomain_batch = []
        while not self.subdomain_queue.empty():
            try:
                subdomain_batch.append(self.subdomain_queue.get_nowait())
            except queue.Empty:
                break
        
        if subdomain_batch:
            self.subdomains_buffer.extend(subdomain_batch)
        
        # Обрабатываем пути
        path_batch = []
        while not self.path_queue.empty():
            try:
                path_batch.append(self.path_queue.get_nowait())
            except queue.Empty:
                break
        
        if path_batch:
            self.paths_buffer.extend(path_batch)
        
        # Обновляем таблицы раз в секунду
        current_time = time.time()
        
        # Обновляем таблицу поддоменов
        if current_time - self.last_subdomains_update >= 1.0 and self.subdomains_buffer:
            self.subdomains_data.extend(self.subdomains_buffer)
            self.update_subdomains_table(self.subdomains_data)
            self.subdomains_buffer = []
            self.last_subdomains_update = current_time
        
        # Обновляем таблицу путей
        if current_time - self.last_paths_update >= 1.0 and self.paths_buffer:
            self.paths_data.extend(self.paths_buffer)
            self.update_paths_table(self.paths_data)
            self.paths_buffer = []
            self.last_paths_update = current_time
        
        # Перезапускаем таймер
        self.gui_update_id = self.after(self.GUI_UPDATE_INTERVAL, self.process_queues)

    def show_context_menu(self, event):
        widget = event.widget
        if widget == self.paths_tree:
            menu = self.paths_context_menu
        elif widget == self.subdomains_tree:
            menu = self.subdomains_context_menu
        else:
            return
        
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    
    def copy_treeview_data(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            return
        
        text_to_copy = ""
        for item in selected_items:
            values = tree.item(item, "values")
            text_to_copy += "\t".join(str(v) for v in values) + "\n"
        
        self.clipboard_clear()
        self.clipboard_append(text_to_copy.strip())
        self.status_var.set("Данные скопированы в буфер обмена")

    def sort_treeview(self, column, tree_type):
        if self.sort_column[tree_type] == column:
            self.sort_direction[tree_type] = "desc" if self.sort_direction[tree_type] == "asc" else "asc"
        else:
            self.sort_column[tree_type] = column
            self.sort_direction[tree_type] = "asc"
        
        if tree_type == "paths":
            tree = self.paths_tree
            data = self.paths_data
        else:
            tree = self.subdomains_tree
            data = self.subdomains_data
        
        items = [(tree.set(item, column), item) for item in tree.get_children('')]
        
        if column == "status" or column == "length":
            try:
                items = [(int(item[0]), item[1]) for item in items]
            except:
                items = [(item[0].lower(), item[1]) for item in items]
        else:
            items = [(item[0].lower(), item[1]) for item in items]
        
        reverse = (self.sort_direction[tree_type] == "desc")
        items.sort(reverse=reverse)
        
        for index, (_, item) in enumerate(items):
            tree.move(item, '', index)
        
        self.update_sort_indicators(tree, tree_type)
    
    def update_sort_indicators(self, tree, tree_type):
        if tree_type == "paths":
            columns = ["url", "status", "type"]  # Обновлено для нового порядка
        else:
            columns = ["subdomain", "ip", "status", "length"]
        
        for col in columns:
            current_text = tree.heading(col)["text"]
            if current_text.endswith(" ↓") or current_text.endswith(" ↑"):
                current_text = current_text[:-2]
            
            if col == self.sort_column[tree_type]:
                arrow = " ↑" if self.sort_direction[tree_type] == "asc" else " ↓"
                tree.heading(col, text=current_text + arrow)
            else:
                tree.heading(col, text=current_text)

    def on_tree_select(self, event):
        selected = self.paths_tree.selection()
        if selected:
            item = self.paths_tree.item(selected)
            values = item['values']
            if values:
                # Обновленный порядок: (url, status, type)
                self.status_var.set(f"Выбран путь: {values[0]} (Статус: {values[1]})")
    
    def update_paths_table(self, data):
        # Очищаем только при первом обновлении
        if self.paths_tree.get_children():
            self.paths_tree.delete(*self.paths_tree.get_children())
        
        # Добавляем новые данные (новый порядок: url, status, type)
        for url, status, path_type in data:
            self.paths_tree.insert("", "end", values=(url, status, path_type))
        
        self.update_sort_indicators(self.paths_tree, "paths")
    
    def update_subdomains_table(self, data):
        # Очищаем только при первом обновлении
        if self.subdomains_tree.get_children():
            self.subdomains_tree.delete(*self.subdomains_tree.get_children())
        
        # Добавляем новые данные
        for subdomain, ip, status, length in data:
            self.subdomains_tree.insert("", "end", values=(subdomain, ip, status, length))
        
        self.update_sort_indicators(self.subdomains_tree, "subdomains")
    
    def clear_paths_table(self):
        self.paths_tree.delete(*self.paths_tree.get_children())
        self.paths_data = []
        self.paths_buffer = []
        self.last_paths_update = 0
        self.sort_column["paths"] = "url"
        self.sort_direction["paths"] = "asc"
        self.update_sort_indicators(self.paths_tree, "paths")
    
    def clear_subdomains_table(self):
        self.subdomains_tree.delete(*self.subdomains_tree.get_children())
        self.subdomains_data = []
        self.subdomains_buffer = []
        self.last_subdomains_update = 0
        self.sort_column["subdomains"] = "subdomain"
        self.sort_direction["subdomains"] = "asc"
        self.update_sort_indicators(self.subdomains_tree, "subdomains")
    
    def get_my_ip(self):
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=3)
            self.my_ip = response.json()["ip"]
        except:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.my_ip = s.getsockname()[0]
                s.close()
            except:
                self.my_ip = "127.0.0.1"
    
    def start_animation(self):
        """Запускаем анимацию"""
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        # Сбрасываем анимацию
        self.animation_pos = 0
        self.bit_particles = []
        self.particle_items = []
        self.animation_complete = False
        self.animation_running = True
        self.last_frame_time = time.time()
        
        # Создаем статичные элементы
        self.setup_animation()
        
        # Запускаем анимацию
        self.animate_connection()
    
    def animate_connection(self):
        """Анимация с оптимизацией"""
        if not self.animation_running:
            return
        
        current_time = time.time()
        elapsed = current_time - self.last_frame_time
        
        # Пропускаем кадры, если отстаем
        if elapsed < self.frame_duration:
            self.animation_id = self.after(1, self.animate_connection)
            return
        
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        if width < 100 or height < 20:
            self.animation_id = self.after(1, self.animate_connection)
            return
        
        # Обновляем текст IP сервера
        server_ip_display = self.get_revealed_ip()
        self.canvas.itemconfig(self.server_ip_text, text=f"{server_ip_display}")
        
        # Генерируем "биты данных" (уменьшено количество)
        if self.scan_active and random.random() < 0.2 and len(self.bit_particles) < 15:
            self.bit_particles.append({
                'pos': 0,
                'size': random.randint(3, 5),
                'speed': random.uniform(0.01, 0.02),
                'color': self.random_green_color()
            })
        
        # Анимируем "биты данных"
        particles_to_remove = []
        for i, bit in enumerate(self.bit_particles):
            # Обновляем позицию
            bit['pos'] += bit['speed']
            
            # Рассчитываем позицию
            x = 50 + (width - 100) * bit['pos']
            
            # Рисуем частицу
            if i < len(self.particle_items):
                # Обновляем существующую частицу
                self.canvas.coords(
                    self.particle_items[i],
                    x - bit['size'], height//2 - bit['size'],
                    x + bit['size'], height//2 + bit['size']
                )
            else:
                # Создаем новую частицу
                particle = self.canvas.create_oval(
                    x - bit['size'], height//2 - bit['size'],
                    x + bit['size'], height//2 + bit['size'],
                    fill=bit['color'], outline=""
                )
                self.particle_items.append(particle)
            
            # Если частица достигла конца, помечаем для удаления
            if bit['pos'] >= 1:
                particles_to_remove.append(bit)
        
        # Удаляем частицы, которые достигли конца
        for bit in particles_to_remove:
            idx = self.bit_particles.index(bit)
            self.bit_particles.remove(bit)
            if idx < len(self.particle_items):
                self.canvas.delete(self.particle_items[idx])
                self.particle_items.pop(idx)
        
        # Обновляем раскрытие IP
        if self.reveal_progress < self.reveal_steps:
            self.reveal_progress += 0.05
        
        # Если сканирование завершено
        if not self.scan_active and not self.animation_complete:
            # Запускаем финальную анимацию
            self.animation_complete = True
            status_text = "✓ Сканирование отменено" if self.scan_cancel else "✓ Сканирование завершено"
            self.canvas.itemconfig(self.status_text, text=status_text,
                                  fill="#e74c3c" if self.scan_cancel else "#2ecc71")
        
        # Обновляем время последнего кадра
        self.last_frame_time = current_time
        
        # Продолжаем анимацию
        self.animation_id = self.after(1, self.animate_connection)
    
    def random_green_color(self):
        r = random.randint(0, 50)
        g = random.randint(200, 255)
        b = random.randint(0, 50)
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def get_revealed_ip(self):
        if self.reveal_progress >= self.reveal_steps:
            return self.server_ip
        
        total_chars = len(self.server_ip)
        revealed_chars = min(total_chars, int(total_chars * (self.reveal_progress / self.reveal_steps)))
        revealed = self.server_ip[:revealed_chars]
        hidden = '*' * (total_chars - revealed_chars)
        return revealed + hidden
    
    def start_scan(self, event=None):
        port = 80
        if self.scan_active:
            return

        target = self.target_entry.get().strip()
        if ":" in target: 
            target, port = target.split(":")
        if not target:
            self.status_var.set("Ошибка: введите домен или IP")
            return
        
        try:
            if not self.is_valid_domain(target):
                ipaddress.ip_address(target)
        except ValueError:
            self.status_var.set("Ошибка: некорректный IP или домен")
            return
        
        self.clear_results()
        self.scan_active = True
        self.scan_cancel = False
        self.status_var.set("Сканирование начато...")
        self.scan_btn.configure(state="disabled", fg_color="#7f8c8d")
        self.cancel_btn.configure(state="normal")
        self.reveal_progress = 0
        
        try:
            self.server_ip = socket.gethostbyname(target)
        except:
            self.server_ip = "Неизвестен"
        
        self.start_animation()
        
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target, port), daemon=True)
        self.scan_thread.start()
    
    def cancel_scan(self):
        if self.scan_active:
            self.scan_cancel = True
            self.status_var.set("Отмена сканирования...")
            self.cancel_btn.configure(state="disabled")
    
    def is_valid_domain(self, domain):
        try:
            socket.gethostbyname(domain)
            return True
        except socket.error:
            return False
    
    def clear_results(self):
        for widget in [self.geo_text, self.ports_text]:
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.configure(state="disabled")
        
        self.clear_paths_table()
        self.clear_subdomains_table()
        
        # Очищаем данные
        self.paths_data = []
        self.subdomains_data = []
        
        # Очищаем очереди
        while not self.subdomain_queue.empty():
            try:
                self.subdomain_queue.get_nowait()
            except queue.Empty:
                pass
        
        while not self.path_queue.empty():
            try:
                self.path_queue.get_nowait()
            except queue.Empty:
                pass
        
        # Останавливаем анимацию
        self.animation_running = False
        if self.animation_id:
            self.after_cancel(self.animation_id)
            self.animation_id = None
            self.canvas.delete("all")
        
        # Очистка карты
        if hasattr(self, 'map_markers'):
            for marker in self.map_markers:
                self.map_widget.delete(marker)
        if hasattr(self, 'connection_line'):
            self.map_widget.delete(self.connection_line)
        
        self.map_widget.set_position(55.7558, 37.6173)
        self.map_widget.set_zoom(3)
    
    def run_scan(self, target, port):
        try:
            # Этап 1: Геолокация
            self.status_var.set("Определение геолокации...")
            self.get_geolocation(target)
            if self.scan_cancel: return
            self.reveal_progress = 5
            
            # Этап 2: Сканирование портов
            self.status_var.set("Сканирование портов...")
            self.scan_ports(target)
            if self.scan_cancel: return
            self.reveal_progress = 10
            
            # Этап 3: Поиск поддоменов
            self.status_var.set("Поиск поддоменов...")
            self.scan_subdomains(target)
            if self.scan_cancel: return
            self.reveal_progress = 12
            
            # Этап 4: Проверка путей
            self.status_var.set("Проверка веб-путей...")
            self.check_web_paths(target, port)
            if self.scan_cancel: return
            self.reveal_progress = 15
            
            self.status_var.set("Сканирование завершено!")
            
        except Exception as e:
            self.status_var.set(f"Ошибка: {str(e)}")
        finally:
            time.sleep(0.7)
            self.scan_active = False
            self.scan_btn.configure(state="normal", fg_color="#27ae60")
            self.cancel_btn.configure(state="disabled")
    
    def get_geolocation(self, target):
        try:
            ip = target if self.is_ip(target) else socket.gethostbyname(target)
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            data = response.json()
            
            self.geo_text.configure(state="normal")
            self.geo_text.delete("1.0", "end")
            
            geo_info = (
                f"IP: {data.get('ip', 'N/A')}\n"
                f"Город: {data.get('city', 'N/A')}\n"
                f"Регион: {data.get('region', 'N/A')}\n"
                f"Страна: {data.get('country', 'N/A')}\n"
                f"Провайдер: {data.get('org', 'N/A')}\n"
            )
            
            self.geo_text.insert("1.0", geo_info)
            self.geo_text.configure(state="disabled")
            
            # Получаем координаты сервера
            server_lat, server_lon = None, None
            if 'loc' in data:
                server_lat, server_lon = map(float, data['loc'].split(','))
            
            # Получаем координаты нашего IP
            my_lat, my_lon = None, None
            try:
                my_response = requests.get(f"https://ipinfo.io/{self.my_ip}/json", timeout=5)
                my_data = my_response.json()
                if 'loc' in my_data:
                    my_lat, my_lon = map(float, my_data['loc'].split(','))
            except:
                pass
            
            # Очищаем предыдущие маркеры
            if hasattr(self, 'map_markers'):
                for marker in self.map_markers:
                    self.map_widget.delete(marker)
            if hasattr(self, 'connection_line'):
                self.map_widget.delete(self.connection_line)
            
            self.map_markers = []
            
            # Добавляем маркер сервера
            if server_lat and server_lon:
                server_marker = self.map_widget.set_marker(
                    server_lat, 
                    server_lon, 
                    text=f"Сервер: {data.get('ip', 'Unknown')}",
                    marker_color_circle="#e74c3c",
                    marker_color_outside="#c0392b",
                    text_color="#e74c3c"
                )
                self.map_markers.append(server_marker)
            
            # Добавляем маркер нашего IP
            if my_lat and my_lon:
                my_marker = self.map_widget.set_marker(
                    my_lat, 
                    my_lon, 
                    text=f"Ваш IP: {self.my_ip}",
                    marker_color_circle="#3498db",
                    marker_color_outside="#2980b9",
                    text_color="#3498db"
                )
                self.map_markers.append(my_marker)
            
            # Если есть оба маркера, рисуем линию
            if len(self.map_markers) == 2:
                self.connection_line = self.map_widget.set_path([
                    (my_lat, my_lon),
                    (server_lat, server_lon)
                ], color="#2ecc71", width=2)
            
            # Устанавливаем масштаб
            if server_lat and server_lon and my_lat and my_lon:
                avg_lat = (server_lat + my_lat) / 2
                avg_lon = (server_lon + my_lon) / 2
                distance = self.calculate_distance(server_lat, server_lon, my_lat, my_lon)
                zoom_level = self.calculate_zoom_level(distance)
                self.map_widget.set_position(avg_lat, avg_lon)
                self.map_widget.set_zoom(zoom_level)
            elif server_lat and server_lon:
                self.map_widget.set_position(server_lat, server_lon)
                self.map_widget.set_zoom(10)
            elif my_lat and my_lon:
                self.map_widget.set_position(my_lat, my_lon)
                self.map_widget.set_zoom(10)
            
        except Exception as e:
            self.geo_text.configure(state="normal")
            self.geo_text.insert("1.0", f"Ошибка геолокации: {str(e)}")
            self.geo_text.configure(state="disabled")
            raise
    
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        R = 6371
        dLat = math.radians(lat2 - lat1)
        dLon = math.radians(lon2 - lon1)
        a = (math.sin(dLat/2) * math.sin(dLat/2) +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dLon/2) * math.sin(dLon/2))
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c
    
    def calculate_zoom_level(self, distance_km):
        if distance_km < 1: return 14
        elif distance_km < 5: return 12
        elif distance_km < 20: return 10
        elif distance_km < 50: return 8
        elif distance_km < 200: return 6
        elif distance_km < 500: return 5
        elif distance_km < 1000: return 4
        else: return 3
    
    def is_ip(self, address):
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def scan_ports(self, target):
        try:
            self.ports_text.configure(state="normal")
            self.ports_text.delete("1.0", "end")
            self.ports_text.insert("1.0", "Идет сканирование портов...\n")
            self.ports_text.update()
            
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
            open_ports = []
            
            def check_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        result = s.connect_ex((target, port))
                        if result == 0:
                            return port
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(check_port, port): port for port in ports}
                for future in concurrent.futures.as_completed(futures):
                    port = futures[future]
                    try:
                        result = future.result()
                        if result:
                            open_ports.append(result)
                            self.ports_text.insert("end", f"Порт {result} открыт\n")
                            self.ports_text.see("end")
                    except Exception:
                        pass
            
            if open_ports:
                self.ports_text.delete("1.0", "end")
                self.ports_text.insert("1.0", "Открытые порты:\n")
                for port in sorted(open_ports):
                    self.ports_text.insert("end", f"- Порт {port}\n")
            else:
                self.ports_text.delete("1.0", "end")
                self.ports_text.insert("1.0", "Открытые порты не найдены\n")
            
            self.ports_text.configure(state="disabled")
        except Exception as e:
            self.ports_text.insert("end", f"\n\nОшибка: {str(e)}")
            self.ports_text.configure(state="disabled")
            raise
    
    def scan_subdomains(self, target):
        try:
            self.clear_subdomains_table()
            self.subdomains_data = []
            
            try:
                with open("subdomains.txt", "r") as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.status_var.set(f"Ошибка чтения файла поддоменов: {str(e)}")
                return

            if self.is_ip(target):
                self.status_var.set("Сканирование поддоменов доступно только для доменов")
                return
                
            domain = target.replace("www.", "") if target.startswith("www.") else target
            total_subdomains = len(subdomains)
            self.status_var.set(f"Проверяем {total_subdomains} поддоменов...")
            
            # Проверяем wildcard DNS
            wildcard_ip = None
            try:
                random_sub = f"randomsub-{random.randint(100000, 999999)}.{domain}"
                wildcard_ip = socket.gethostbyname(random_sub)
                self.status_var.set(f"Обнаружен wildcard DNS! Все поддомены указывают на {wildcard_ip}")
            except socket.gaierror:
                wildcard_ip = None
            
            # Получаем эталонные страницы 404
            not_found_templates = {}
            protocols = ["http", "https"]
            
            if wildcard_ip:
                for protocol in protocols:
                    try:
                        url_404 = f"{protocol}://{random_sub}"
                        response_404 = requests.get(
                            url_404,
                            timeout=3, 
                            verify=False,
                            allow_redirects=False
                        )
                        not_found_templates[protocol] = {
                            "hash": hashlib.md5(response_404.content).hexdigest(),
                            "status": response_404.status_code
                        }
                    except Exception:
                        not_found_templates[protocol] = None
            
            # Улучшенные User-Agents
            USER_AGENTS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
            ]
            
            # Функция для проверки поддомена
            def check_subdomain(sub):
                full_domain = f"{sub}.{domain}"
                
                try:
                    # Проверяем DNS запись
                    ip = socket.gethostbyname(full_domain)
                    
                    # Если wildcard и IP совпадает - пропускаем
                    if wildcard_ip and ip == wildcard_ip:
                        return None
                    
                    # Проверяем доступность
                    for protocol in protocols:
                        try:
                            headers = {"User-Agent": random.choice(USER_AGENTS)}
                            url = f"{protocol}://{full_domain}"

                            response = requests.get(
                                url, 
                                headers=headers, 
                                timeout=2, 
                                verify=False,
                                allow_redirects=False
                            )
                            
                            content_length = len(response.content)
                            
                            # Фильтруем недоступные ресурсы
                            if response.status_code < 400:
                                # Для wildcard DNS проверяем контент
                                if wildcard_ip:
                                    if protocol in not_found_templates and not_found_templates[protocol]:
                                        current_hash = hashlib.md5(response.content).hexdigest()
                                        if current_hash == not_found_templates[protocol]["hash"]:
                                            continue
                                
                                return full_domain, ip, response.status_code, content_length
                                
                        except (requests.ConnectionError, requests.Timeout):
                            continue
                        except Exception:
                            continue
                    
                except socket.gaierror:
                    pass
                except Exception as e:
                    pass
                    
                return None
            
            # Оптимальное количество потоков
            max_workers = 10 if wildcard_ip else 300
            
            processed_count = 0
            found_count = 0
            last_update_time = time.time()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
                
                for future in concurrent.futures.as_completed(futures):
                    if self.scan_cancel:
                        for f in futures:
                            f.cancel()
                        self.status_var.set("Сканирование отменено")
                        break
                    
                    processed_count += 1
                    
                    try:
                        result = future.result()
                        if result:
                            found_count += 1
                            self.subdomain_queue.put(result)
                            
                    except Exception as e:
                        pass
                    
                    # Обновляем статус каждые 100 записей
                    if processed_count % 100 == 0:
                        self.status_var.set(
                            f"Проверено поддоменов: {processed_count}/{total_subdomains}, "
                            f"Найдено: {found_count}"
                        )
            
            if not self.scan_cancel:
                self.status_var.set(f"Найдено {found_count} поддоменов")
                
        except Exception as e:
            self.status_var.set(f"Ошибка сканирования поддоменов: {str(e)}")
    
    def check_web_paths(self, target, port):
        try:
            self.clear_paths_table()
            self.paths_data = []
            
            try:
                with open("paths.txt", "r") as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.status_var.set(f"Ошибка чтения файла: {str(e)}")
                return

            USER_AGENTS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"
            ]
            
            protocols = ["http", "https"]
            urls = []
            
            # Формируем URL
            for protocol in protocols:
                if port != 80:
                    base_url = f"{protocol}://{target}:{port}"
                else:
                    base_url = f"{protocol}://{target}"
                urls.append(base_url)
                
                for path in paths:
                    if path.startswith("/"):
                        url = base_url + path
                    else:
                        url = base_url + "/" + path
                    urls.append(url)
            
            total_urls = len(urls)
            self.status_var.set(f"Проверяем {total_urls} веб-путей...")
            
            # Функция для проверки URL
            def check_single_url(url):
                try:
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    
                    with httpx.Client(follow_redirects=True, timeout=5, verify=False) as client:
                        response = client.get(url, headers=headers)
                        
                        if 200 <= response.status_code < 400:
                            return url, response.status_code, "OK"
                        elif response.status_code == 403 and len(response.text) > 100:
                            return url, response.status_code, "Forbidden"
                        elif 300 <= response.status_code < 400:
                            location = response.headers.get('Location', '')
                            if location and not location.startswith(('http://', 'https://')):
                                location = url + location
                            return f"Redirect: {url} -> {location}", response.status_code, "Redirect"
                except httpx.TimeoutException:
                    return None
                except httpx.ConnectError:
                    return None
                except Exception:
                    return None
            
            processed_count = 0
            found_count = 0
            last_update_time = time.time()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_url = {executor.submit(check_single_url, url): url for url in urls}
                
                for future in concurrent.futures.as_completed(future_to_url):
                    if self.scan_cancel:
                        for f in future_to_url:
                            f.cancel()
                        self.status_var.set("Сканирование отменено")
                        break
                    
                    processed_count += 1
                    
                    try:
                        result = future.result()
                        if result:
                            found_count += 1
                            # Сохраняем в порядке: (url, status, type)
                            self.path_queue.put((result[0], result[1], result[2]))
                            
                    except Exception as e:
                        pass
                    
                    # Обновляем статус каждые 100 записей (ИСПРАВЛЕН ТЕКСТ)
                    if processed_count % 100 == 0:
                        self.status_var.set(f"Проверено веб-путей: {processed_count}/{total_urls}, Найдено: {found_count}")
            
            if not self.scan_cancel:
                self.status_var.set(f"Сканирование завершено! Найдено {found_count} веб-путей")
            
        except Exception as e:
            self.status_var.set(f"Ошибка: {str(e)}")

if __name__ == "__main__":
    app = UltraSimpleScanner()
    app.mainloop()