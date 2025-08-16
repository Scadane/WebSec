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
from localization import translations
import ctypes
from PIL import Image
from settings import *
# ====================== ГЛОБАЛЬНЫЕ НАСТРОЙКИ ======================
# Настройки DPI и масштабирования
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # Для Windows 10/11
except:
    pass

# Настройки внешнего вида
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Начальное значение масштабирования
SCALING_FACTOR = 0.95  # Основной параметр масштабирования

# Применяем масштабирование
ctk.set_widget_scaling(SCALING_FACTOR)
ctk.set_window_scaling(SCALING_FACTOR)

# Базовые размеры (до масштабирования)
BASE_FONT_SIZE = 11
BASE_ROW_HEIGHT = 40
BASE_ENTRY_HEIGHT = 40
BASE_BUTTON_WIDTH = 120
BASE_WINDOW_WIDTH = 1200
BASE_WINDOW_HEIGHT = 800

# Масштабированные размеры
TABLE_FONT_SIZE = int(BASE_FONT_SIZE * SCALING_FACTOR)
TABLE_ROW_HEIGHT = int(BASE_ROW_HEIGHT * SCALING_FACTOR)
TABLE_HEADER_FONT = ('Arial', TABLE_FONT_SIZE, 'bold')
ENTRY_HEIGHT = int(BASE_ENTRY_HEIGHT * SCALING_FACTOR)
BUTTON_WIDTH = int(BASE_BUTTON_WIDTH * SCALING_FACTOR)
WINDOW_WIDTH = int(BASE_WINDOW_WIDTH * SCALING_FACTOR)
WINDOW_HEIGHT = int(BASE_WINDOW_HEIGHT * SCALING_FACTOR)

# Цвета
BG_COLOR = "#2a2d2e"
TREEVIEW_BG = "#292828"
TREEVIEW_FG = "white"
TREEVIEW_FIELD_BG = "#2a2d2e"
HEADER_BG = "#1e1e1e"
HEADER_FG = "#ffffff"
SELECTION_BG = "#22559b"
SELECTION_FG = "white"

# Размеры столбцов (базовые, будут масштабироваться)
COLUMN_WIDTHS = {
    'paths': {
        'url': int(350 * SCALING_FACTOR),
        'status': int(100 * SCALING_FACTOR),
        'type': int(100 * SCALING_FACTOR)
    },
    'subdomains': {
        'subdomain': int(130 * SCALING_FACTOR),
        'ip': int(130 * SCALING_FACTOR),
        'status': int(100 * SCALING_FACTOR),
        'length': int(100 * SCALING_FACTOR)
    }
}

# Минимальные ширины столбцов
MIN_COLUMN_WIDTHS = {
    'paths': {
        'url': int(250 * SCALING_FACTOR),
        'status': int(80 * SCALING_FACTOR),
        'type': int(80 * SCALING_FACTOR)
    },
    'subdomains': {
        'subdomain': int(120 * SCALING_FACTOR),
        'ip': int(100 * SCALING_FACTOR),
        'status': int(50 * SCALING_FACTOR),
        'length': int(50 * SCALING_FACTOR)
    }
}

# Отключение предупреждений
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UltraSimpleScanner(ctk.CTk):
    def __init__(self):
        # Загрузка настроек перед инициализацией интерфейса
        self.settings_manager = SettingsManager()
        settings = self.settings_manager.load_settings()
        
        # Устанавливаем язык по умолчанию
        self.current_language = settings['language']
        self.translations = translations
        
        # Устанавливаем масштабирование
        global SCALING_FACTOR
        SCALING_FACTOR = settings['scaling'] / 100.0
        
        # Применяем масштабирование
        ctk.set_widget_scaling(SCALING_FACTOR)
        ctk.set_window_scaling(SCALING_FACTOR)
        
        # Пересчитываем размеры
        TABLE_FONT_SIZE = int(BASE_FONT_SIZE * SCALING_FACTOR)
        TABLE_ROW_HEIGHT = int(BASE_ROW_HEIGHT * SCALING_FACTOR)
        ENTRY_HEIGHT = int(BASE_ENTRY_HEIGHT * SCALING_FACTOR)
        BUTTON_WIDTH = int(BASE_BUTTON_WIDTH * SCALING_FACTOR)
        WINDOW_WIDTH = int(BASE_WINDOW_WIDTH * SCALING_FACTOR)
        WINDOW_HEIGHT = int(BASE_WINDOW_HEIGHT * SCALING_FACTOR)
        
        super().__init__()
        
        # Основные настройки окна с учетом масштабирования
        self.title(self._("app_title"))
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(int(1000 * SCALING_FACTOR), int(700 * SCALING_FACTOR))
        self.iconbitmap("iconw.ico")

        # Настройка сетки
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        
        # Верхняя панель
        self.create_header()
        
        # Панель анимации
        self.create_animation_panel()
        
        # Основные панели
        self.create_main_panels()
        
        # Статус бар
        self.create_status_bar()
        
        # Инициализация переменных
        self.scan_active = False
        self.scan_cancel = False
        self.marker = None
        self.scan_thread = None
        self.paths_data = []
        self.subdomains_data = []
        self.subdomain_queue = queue.Queue()
        self.path_queue = queue.Queue()
        self.gui_update_id = None
        self.GUI_UPDATE_INTERVAL = 1000
        self.paths_buffer = []
        self.subdomains_buffer = []
        self.last_paths_update = 0
        self.last_subdomains_update = 0
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
        self.frame_duration = 1/30
        self.static_items = []
        self.particle_items = []
        self.sort_column = {
            "paths": "url",
            "subdomains": "subdomain"
        }
        self.sort_direction = {
            "paths": "asc",
            "subdomains": "asc"
        }
        
        # Флаг для отслеживания движения слайдера
        self.scale_slider_moving = False
        
        # Получаем наш IP
        self.get_my_ip()
        
        # Запускаем обработчик очередей
        self.after(100, self.process_queues)

    def _(self, key):
        """Метод для получения перевода по ключу"""
        return self.translations[self.current_language].get(key, key)
    
    def create_header(self):
        """Создает верхнюю панель с полем ввода и кнопками"""
        self.header_frame = ctk.CTkFrame(self, corner_radius=int(10 * SCALING_FACTOR), fg_color="#2c3e50")
        self.header_frame.grid(row=0, column=0, columnspan=2, padx=int(10 * SCALING_FACTOR), pady=int(10 * SCALING_FACTOR), sticky="nsew")
        
        self.target_entry = ctk.CTkEntry(
            self.header_frame, 
            placeholder_text=self._("target_placeholder"),
            width=int(400 * SCALING_FACTOR),
            height=ENTRY_HEIGHT,
            font=("Arial", int(16 * SCALING_FACTOR)),
            corner_radius=int(8 * SCALING_FACTOR)
        )
        self.target_entry.pack(side="left", padx=int(20 * SCALING_FACTOR), pady=int(15 * SCALING_FACTOR), fill="x", expand=True)
        self.target_entry.bind("<Return>", self.start_scan)
        
        self.scan_btn = ctk.CTkButton(
            self.header_frame, 
            text=self._("scan_button"),
            command=self.start_scan,
            height=ENTRY_HEIGHT,
            width=BUTTON_WIDTH,
            font=("Arial", int(14 * SCALING_FACTOR), "bold"),
            fg_color="#27ae60",
            hover_color="#2ecc71",
            corner_radius=int(8 * SCALING_FACTOR)
        )
        self.scan_btn.pack(side="right", padx=int(20 * SCALING_FACTOR), pady=int(15 * SCALING_FACTOR))
        
        self.cancel_btn = ctk.CTkButton(
            self.header_frame, 
            text=self._("cancel_button"),
            command=self.cancel_scan,
            height=ENTRY_HEIGHT,
            width=int(100 * SCALING_FACTOR),
            font=("Arial", int(14 * SCALING_FACTOR)),
            fg_color="#e74c3c",
            hover_color="#c0392b",
            corner_radius=int(8 * SCALING_FACTOR),
            state="disabled"
        )
        self.cancel_btn.pack(side="right", padx=(0, int(10 * SCALING_FACTOR)), pady=int(15 * SCALING_FACTOR))

    def create_animation_panel(self):
        """Создает панель с анимацией подключения"""
        self.connection_frame = ctk.CTkFrame(self, height=int(35 * SCALING_FACTOR), corner_radius=int(10 * SCALING_FACTOR), fg_color="#1a1a1a")
        self.connection_frame.grid(row=1, column=0, columnspan=2, padx=int(10 * SCALING_FACTOR), pady=(0, int(10 * SCALING_FACTOR)), sticky="ew")
        self.connection_frame.grid_propagate(False)
        self.grid_rowconfigure(1, weight=0, minsize=int(25 * SCALING_FACTOR))
        
        self.canvas = tk.Canvas(self.connection_frame, bg=self.connection_frame.cget("fg_color"), highlightthickness=0, height=int(50 * SCALING_FACTOR))
        self.canvas.pack(fill="both", expand=False, padx=int(20 * SCALING_FACTOR), pady=int(10 * SCALING_FACTOR))

    def create_main_panels(self):
        """Создает основные панели с информацией и картой"""
        # Левая панель
        self.info_frame = ctk.CTkFrame(self, corner_radius=int(10 * SCALING_FACTOR))
        self.info_frame.grid(row=2, column=0, padx=(int(20 * SCALING_FACTOR), int(10 * SCALING_FACTOR)), pady=(0, int(20 * SCALING_FACTOR)), sticky="nsew")
        self.info_frame.grid_rowconfigure(0, weight=1)
        self.info_frame.grid_columnconfigure(0, weight=1)
        
        # Правая панель
        self.map_frame = ctk.CTkFrame(self, corner_radius=int(10 * SCALING_FACTOR))
        self.map_frame.grid(row=2, column=1, padx=(int(10 * SCALING_FACTOR), int(20 * SCALING_FACTOR)), pady=(0, int(20 * SCALING_FACTOR)), sticky="nsew")
        self.map_frame.grid_rowconfigure(0, weight=1)
        self.map_frame.grid_columnconfigure(0, weight=1)
        
        # Карта
        self.map_widget = tkintermapview.TkinterMapView(
            self.map_frame, 
            corner_radius=int(8 * SCALING_FACTOR)
        )
        self.map_widget.grid(row=0, column=0, padx=int(10 * SCALING_FACTOR), pady=int(10 * SCALING_FACTOR), sticky="nsew")
        self.map_widget.set_position(55.7558, 37.6173)
        self.map_widget.set_zoom(3)
        
        # Контейнер для информации
        self.create_tabview()

    def create_tabview(self):
        """Создает вкладки с информацией"""
        self.tabview = ctk.CTkTabview(self.info_frame, corner_radius=int(8 * SCALING_FACTOR))
        self.tabview.grid(row=0, column=0, padx=int(10 * SCALING_FACTOR), pady=int(10 * SCALING_FACTOR), sticky="nsew")
        self.tabview.grid_columnconfigure(0, weight=1)

        # Создаем вкладки
        self.tab_geo = self.tabview.add(self._("geo_tab"))
        self.tab_paths = self.tabview.add(self._("paths_tab"))
        self.tab_subdomains = self.tabview.add(self._("subdomains_tab"))

        self.tabview.set(self._("geo_tab"))

        # Вкладка геолокации
        self.create_geo_tab()
        
        # Вкладка веб-путей
        self.create_paths_tab()
        
        # Вкладка поддоменов
        self.create_subdomains_tab()

    def create_geo_tab(self):
        """Создает вкладку геолокации"""
        self.tab_geo.grid_columnconfigure(0, weight=1)
        self.tab_geo.grid_rowconfigure(0, weight=0)
        self.tab_geo.grid_rowconfigure(1, weight=1)

        geo_frame = ctk.CTkFrame(self.tab_geo, corner_radius=int(8 * SCALING_FACTOR))
        geo_frame.grid(row=0, column=0, padx=int(5 * SCALING_FACTOR), pady=int(5 * SCALING_FACTOR), sticky="ew")

        ctk.CTkLabel(
            geo_frame, 
            text=self._("geo_location"),
            font=("Arial", int(14 * SCALING_FACTOR), "bold"),
            anchor="w"
        ).pack(fill="x", padx=int(10 * SCALING_FACTOR), pady=(int(10 * SCALING_FACTOR), int(5 * SCALING_FACTOR)))

        self.geo_text = ctk.CTkTextbox(
            geo_frame, 
            height=int(150 * SCALING_FACTOR),
            wrap="word",
            font=("Arial", int(13 * SCALING_FACTOR)),
            activate_scrollbars=False
        )
        self.geo_text.pack(fill="x", padx=int(10 * SCALING_FACTOR), pady=(0, int(10 * SCALING_FACTOR)))
        self.geo_text.insert("1.0", self._("geo_location") + " " + self._("ready_status"))
        self.geo_text.configure(state="disabled")

        # Секция портов
        ports_frame = ctk.CTkFrame(self.tab_geo, corner_radius=int(8 * SCALING_FACTOR))
        ports_frame.grid(row=1, column=0, padx=int(5 * SCALING_FACTOR), pady=int(5 * SCALING_FACTOR), sticky="nsew")
        ports_frame.grid_rowconfigure(0, weight=1)
        ports_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            ports_frame, 
            text=self._("open_ports"),
            font=("Arial", int(13 * SCALING_FACTOR), "bold"),
            anchor="w"
        ).pack(fill="x", padx=int(10 * SCALING_FACTOR), pady=(int(10 * SCALING_FACTOR), int(5 * SCALING_FACTOR)))

        self.ports_text = ctk.CTkTextbox(
            ports_frame, 
            wrap="word",
            font=("Consolas", int(14 * SCALING_FACTOR)),
            activate_scrollbars=True
        )
        self.ports_text.pack(fill="both", expand=True, padx=int(10 * SCALING_FACTOR), pady=(0, int(10 * SCALING_FACTOR)))
        self.ports_text.insert("1.0", self._("open_ports") + " " + self._("ready_status"))
        self.ports_text.configure(state="disabled")

    def create_paths_tab(self):
        """Создает вкладку с веб-путями"""
        self.tab_paths.grid_columnconfigure(0, weight=1)
        self.tab_paths.grid_rowconfigure(0, weight=0)
        self.tab_paths.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self.tab_paths, 
            text=self._("available_paths"),
            font=("Arial", int(14 * SCALING_FACTOR), "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=int(15 * SCALING_FACTOR), pady=(int(10 * SCALING_FACTOR), int(5 * SCALING_FACTOR)), sticky="w")

        tree_frame = ctk.CTkFrame(self.tab_paths, corner_radius=int(8 * SCALING_FACTOR), fg_color=BG_COLOR)
        tree_frame.grid(row=1, column=0, padx=int(10 * SCALING_FACTOR), pady=(0, int(10 * SCALING_FACTOR)), sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        # Стиль для Treeview
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("Treeview", 
                       background=TREEVIEW_BG,
                       foreground=TREEVIEW_FG,
                       rowheight=TABLE_ROW_HEIGHT,
                       fieldbackground=TREEVIEW_FIELD_BG,
                       font=('Arial', TABLE_FONT_SIZE),
                       borderwidth=0,
                       highlightthickness=0,
                       relief="flat")
        
        style.configure("Treeview.Heading", 
                        background=HEADER_BG, 
                        foreground=HEADER_FG,
                        font=TABLE_HEADER_FONT,
                        padding=(int(5 * SCALING_FACTOR), int(5 * SCALING_FACTOR)),
                        relief="flat",
                        borderwidth=0)
        
        style.map("Treeview", 
                  background=[('selected', SELECTION_BG)],
                  foreground=[('selected', SELECTION_FG)])
        
        style.map("Treeview.Heading", 
                  background=[('active', "#3d3d3d")])

        # Treeview для путей
        self.paths_tree = ttk.Treeview(
            tree_frame,
            columns=("url", "status", "type"),
            show="headings",
            selectmode="browse",
            style="Treeview"
        )
        
        self.paths_tree.heading("url", text=self._("url_column"), anchor="w", command=lambda: self.sort_treeview("url", "paths"))
        self.paths_tree.heading("status", text=self._("status_column"), anchor="w", command=lambda: self.sort_treeview("status", "paths"))
        self.paths_tree.heading("type", text=self._("type_column"), anchor="w", command=lambda: self.sort_treeview("type", "paths"))
        
        self.paths_tree.column("url", width=COLUMN_WIDTHS['paths']['url'], minwidth=MIN_COLUMN_WIDTHS['paths']['url'], stretch=True)
        self.paths_tree.column("status", width=COLUMN_WIDTHS['paths']['status'], minwidth=MIN_COLUMN_WIDTHS['paths']['status'], stretch=False)
        self.paths_tree.column("type", width=COLUMN_WIDTHS['paths']['type'], minwidth=MIN_COLUMN_WIDTHS['paths']['type'], stretch=False)
        
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
        self.paths_context_menu.add_command(label=self._("copy_button"), command=lambda: self.copy_treeview_data(self.paths_tree))
        self.paths_tree.bind("<Button-3>", self.show_context_menu)

    def create_subdomains_tab(self):
        """Создает вкладку с поддоменами"""
        self.tab_subdomains.grid_columnconfigure(0, weight=1)
        self.tab_subdomains.grid_rowconfigure(0, weight=0)
        self.tab_subdomains.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self.tab_subdomains, 
            text=self._("found_subdomains"),
            font=("Arial", int(14 * SCALING_FACTOR), "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=int(15 * SCALING_FACTOR), pady=(int(10 * SCALING_FACTOR), int(5 * SCALING_FACTOR)), sticky="w")

        subdomains_frame = ctk.CTkFrame(self.tab_subdomains, corner_radius=int(8 * SCALING_FACTOR), fg_color=BG_COLOR)
        subdomains_frame.grid(row=1, column=0, padx=int(10 * SCALING_FACTOR), pady=(0, int(10 * SCALING_FACTOR)), sticky="nsew")
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
        
        self.subdomains_tree.heading("subdomain", text=self._("subdomain_column"), anchor="w", command=lambda: self.sort_treeview("subdomain", "subdomains"))
        self.subdomains_tree.heading("ip", text=self._("ip_column"), anchor="w", command=lambda: self.sort_treeview("ip", "subdomains"))
        self.subdomains_tree.heading("status", text=self._("status_column"), anchor="w", command=lambda: self.sort_treeview("status", "subdomains"))
        self.subdomains_tree.heading("length", text=self._("length_column"), anchor="w", command=lambda: self.sort_treeview("length", "subdomains"))
        
        self.subdomains_tree.column("subdomain", width=COLUMN_WIDTHS['subdomains']['subdomain'], 
                                  minwidth=MIN_COLUMN_WIDTHS['subdomains']['subdomain'], stretch=True)
        self.subdomains_tree.column("ip", width=COLUMN_WIDTHS['subdomains']['ip'], 
                                   minwidth=MIN_COLUMN_WIDTHS['subdomains']['ip'], stretch=True)
        self.subdomains_tree.column("status", width=COLUMN_WIDTHS['subdomains']['status'], 
                                   minwidth=MIN_COLUMN_WIDTHS['subdomains']['status'], stretch=False)
        self.subdomains_tree.column("length", width=COLUMN_WIDTHS['subdomains']['length'], 
                                   minwidth=MIN_COLUMN_WIDTHS['subdomains']['length'], stretch=False)
        
        subdomains_scrollbar = ttk.Scrollbar(
            subdomains_frame,
            orient="vertical",
            command=self.subdomains_tree.yview
        )
        self.subdomains_tree.configure(yscrollcommand=subdomains_scrollbar.set)
        
        self.subdomains_tree.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        subdomains_scrollbar.grid(row=0, column=1, sticky="ns", padx=0, pady=0)
        
        self.subdomains_context_menu = tk.Menu(self, tearoff=0)
        self.subdomains_context_menu.add_command(label=self._("copy_button"), command=lambda: self.copy_treeview_data(self.subdomains_tree))
        self.subdomains_tree.bind("<Button-3>", self.show_context_menu)

    def create_status_bar(self):
        """Создает статус бар"""
        self.status_frame = ctk.CTkFrame(self, fg_color="#333333", corner_radius=0)
        self.status_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar(value=self._("ready_status"))
        self.status_bar = ctk.CTkLabel(
            self.status_frame, 
            textvariable=self.status_var,
            anchor="w",
            font=("Arial", int(12 * SCALING_FACTOR)),
            fg_color="transparent",
            corner_radius=0,
            padx=int(20 * SCALING_FACTOR)
        )
        self.status_bar.grid(row=0, column=0, sticky="ew")
        
        # Кнопка настроек
        self.settings_btn = ctk.CTkButton(
            self.status_frame,
            text="⚙",
            width=int(30 * SCALING_FACTOR),
            height=int(30 * SCALING_FACTOR),
            font=("Arial", int(14 * SCALING_FACTOR), "bold"),
            fg_color="transparent",
            hover_color="#555555",
            text_color="#ffffff",
            command=self.show_settings,
            corner_radius=0
        )
        self.settings_btn.grid(row=0, column=1, padx=(0, int(5 * SCALING_FACTOR)), sticky="e")
        
        # Кнопка информации
        self.info_btn = ctk.CTkButton(
            self.status_frame,
            text="ℹ",
            width=int(30 * SCALING_FACTOR),
            height=int(30 * SCALING_FACTOR),
            font=("Arial", int(14 * SCALING_FACTOR), "bold"),
            fg_color="transparent",
            hover_color="#555555",
            text_color="#ffffff",
            command=self.show_info,
            corner_radius=0
        )
        self.info_btn.grid(row=0, column=2, padx=(0, int(10 * SCALING_FACTOR)), sticky="e")

    def setup_animation(self):
        """Создаем статичные элементы анимации"""
        self.canvas.delete("all")
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        if width < 100 or height < 20:
            return
            
        # Рисуем линию подключения
        line = self.canvas.create_line(
            int(50 * SCALING_FACTOR), height//2, 
            width-int(50 * SCALING_FACTOR), height//2, 
            fill="#333", width=int(2 * SCALING_FACTOR), dash=(4, 2))
        self.static_items.append(line)
        
        # Рисуем точки подключения
        dot1 = self.canvas.create_oval(
            int(45 * SCALING_FACTOR), height//2-int(3 * SCALING_FACTOR),
            int(55 * SCALING_FACTOR), height//2+int(3 * SCALING_FACTOR),
            fill="#3498db", outline="")
        dot2 = self.canvas.create_oval(
            width-int(55 * SCALING_FACTOR), height//2-int(3 * SCALING_FACTOR),
            width-int(45 * SCALING_FACTOR), height//2+int(3 * SCALING_FACTOR),
            fill="#e74c3c", outline="")
        self.static_items.extend([dot1, dot2])
        
        # Создаем текст для IP
        self.my_ip_text = self.canvas.create_text(
            int(10 * SCALING_FACTOR), height//2-int(10 * SCALING_FACTOR), 
            text=f"{self.my_ip}", 
            anchor="w", fill="#3498db", font=("Arial", int(12 * SCALING_FACTOR)))
        self.server_ip_text = self.canvas.create_text(
            width-int(10 * SCALING_FACTOR), height//2-int(10 * SCALING_FACTOR), 
            text=f"{self.hidden_ip}", 
            anchor="e", fill="#e74c3c", font=("Arial", int(12 * SCALING_FACTOR)))
        self.static_items.extend([self.my_ip_text, self.server_ip_text])
        
        # Текст статуса
        self.status_text = self.canvas.create_text(
            width//2, height//2+int(10 * SCALING_FACTOR), 
            text="", 
            fill="#2ecc71", font=("Arial", int(10 * SCALING_FACTOR), "bold"))
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
        self.status_var.set(self._("data_copied"))

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
            columns = ["url", "status", "type"]
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
                self.status_var.set(self._("selected_path").format(values[0], values[1]))
    
    def update_paths_table(self, data):
        if self.paths_tree.get_children():
            self.paths_tree.delete(*self.paths_tree.get_children())
        
        for url, status, path_type in data:
            self.paths_tree.insert("", "end", values=(url, status, path_type))
        
        self.update_sort_indicators(self.paths_tree, "paths")
    
    def update_subdomains_table(self, data):
        if self.subdomains_tree.get_children():
            self.subdomains_tree.delete(*self.subdomains_tree.get_children())
        
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
        
        self.animation_pos = 0
        self.bit_particles = []
        self.particle_items = []
        self.animation_complete = False
        self.animation_running = True
        self.last_frame_time = time.time()
        
        self.setup_animation()
        self.animate_connection()
    
    def animate_connection(self):
        """Анимация с оптимизацией"""
        if not self.animation_running:
            return
        
        current_time = time.time()
        elapsed = current_time - self.last_frame_time
        
        if elapsed < self.frame_duration:
            self.animation_id = self.after(1, self.animate_connection)
            return
        
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        if width < 100 or height < 20:
            self.animation_id = self.after(1, self.animate_connection)
            return
        
        server_ip_display = self.get_revealed_ip()
        self.canvas.itemconfig(self.server_ip_text, text=f"{server_ip_display}")
        
        if self.scan_active and random.random() < 0.2 and len(self.bit_particles) < 15:
            self.bit_particles.append({
                'pos': 0,
                'size': random.randint(3, 5),
                'speed': random.uniform(0.01, 0.02),
                'color': self.random_green_color()
            })
        
        particles_to_remove = []
        for i, bit in enumerate(self.bit_particles):
            bit['pos'] += bit['speed']
            x = 50 + (width - 100) * bit['pos']
            
            if i < len(self.particle_items):
                self.canvas.coords(
                    self.particle_items[i],
                    x - bit['size'], height//2 - bit['size'],
                    x + bit['size'], height//2 + bit['size']
                )
            else:
                particle = self.canvas.create_oval(
                    x - bit['size'], height//2 - bit['size'],
                    x + bit['size'], height//2 + bit['size'],
                    fill=bit['color'], outline=""
                )
                self.particle_items.append(particle)
            
            if bit['pos'] >= 1:
                particles_to_remove.append(bit)
        
        for bit in particles_to_remove:
            idx = self.bit_particles.index(bit)
            self.bit_particles.remove(bit)
            if idx < len(self.particle_items):
                self.canvas.delete(self.particle_items[idx])
                self.particle_items.pop(idx)
        
        if self.reveal_progress < self.reveal_steps:
            self.reveal_progress += 0.05
        
        if not self.scan_active and not self.animation_complete:
            self.animation_complete = True
            status_text = f"✓ {self._('scan_canceled')}" if self.scan_cancel else f"✓ {self._('scan_completed')}"
            self.canvas.itemconfig(self.status_text, text=status_text,
                                  fill="#e74c3c" if self.scan_cancel else "#2ecc71")
        
        self.last_frame_time = current_time
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
            self.status_var.set(self._("error_target"))
            return
        
        try:
            if not self.is_valid_domain(target):
                ipaddress.ip_address(target)
        except ValueError:
            self.status_var.set(self._("error_invalid"))
            return
        
        self.clear_results()
        self.scan_active = True
        self.scan_cancel = False
        self.status_var.set(self._("scanning_status"))
        self.scan_btn.configure(state="disabled", fg_color="#7f8c8d")
        self.cancel_btn.configure(state="normal")
        self.reveal_progress = 0
        
        try:
            self.server_ip = socket.gethostbyname(target)
        except:
            self.server_ip = self._("unknown")
        
        self.start_animation()
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target, port), daemon=True)
        self.scan_thread.start()
    
    def cancel_scan(self):
        if self.scan_active:
            self.scan_cancel = True
            self.status_var.set(self._("scan_canceled"))
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
        self.paths_data = []
        self.subdomains_data = []
        
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
        
        self.animation_running = False
        if self.animation_id:
            self.after_cancel(self.animation_id)
            self.animation_id = None
            self.canvas.delete("all")
        
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
            self.status_var.set(self._("geo_location") + "...")
            self.get_geolocation(target)
            if self.scan_cancel: return
            self.reveal_progress = 5
            
            # Этап 2: Сканирование портов
            self.status_var.set(self._("port_scanning"))
            self.scan_ports(target)
            if self.scan_cancel: return
            self.reveal_progress = 10
            
            # Этап 3: Поиск поддоменов
            self.status_var.set(self._("subdomain_scanning"))
            self.scan_subdomains(target)
            if self.scan_cancel: return
            self.reveal_progress = 12
            
            # Этап 4: Проверка путей
            self.status_var.set(self._("webpath_scanning"))
            self.check_web_paths(target, port)
            if self.scan_cancel: return
            self.reveal_progress = 15
            
            self.status_var.set(self._("scan_completed"))
            
        except Exception as e:
            self.status_var.set(f"{self._('error')}: {str(e)}")
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
            
            geo_info = self._("geo_info").format(
                ip=data.get('ip', 'N/A'),
                city=data.get('city', 'N/A'),
                region=data.get('region', 'N/A'),
                country=data.get('country', 'N/A'),
                org=data.get('org', 'N/A')
            )
            
            self.geo_text.insert("1.0", geo_info)
            self.geo_text.configure(state="disabled")
            
            server_lat, server_lon = None, None
            if 'loc' in data:
                server_lat, server_lon = map(float, data['loc'].split(','))
            
            my_lat, my_lon = None, None
            try:
                my_response = requests.get(f"https://ipinfo.io/{self.my_ip}/json", timeout=5)
                my_data = my_response.json()
                if 'loc' in my_data:
                    my_lat, my_lon = map(float, my_data['loc'].split(','))
            except:
                pass
            
            if hasattr(self, 'map_markers'):
                for marker in self.map_markers:
                    self.map_widget.delete(marker)
            if hasattr(self, 'connection_line'):
                self.map_widget.delete(self.connection_line)
            
            self.map_markers = []
            
            if server_lat and server_lon:
                server_marker = self.map_widget.set_marker(
                    server_lat, 
                    server_lon, 
                    text=f"{self._('server')}: {data.get('ip', self._('unknown'))}",
                    marker_color_circle="#e74c3c",
                    marker_color_outside="#c0392b",
                    text_color="#e74c3c"
                )
                self.map_markers.append(server_marker)
            
            if my_lat and my_lon:
                my_marker = self.map_widget.set_marker(
                    my_lat, 
                    my_lon, 
                    text=f"{self._('your_ip')}: {self.my_ip}",
                    marker_color_circle="#3498db",
                    marker_color_outside="#2980b9",
                    text_color="#3498db"
                )
                self.map_markers.append(my_marker)
            
            if len(self.map_markers) == 2:
                self.connection_line = self.map_widget.set_path([
                    (my_lat, my_lon),
                    (server_lat, server_lon)
                ], color="#2ecc71", width=2)
            
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
            self.geo_text.insert("1.0", self._("error_geo").format(str(e)))
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
            self.ports_text.insert("1.0", self._("port_scanning") + "\n")
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
                            self.ports_text.insert("end", f"{self._('port')} {result} {self._('open')}\n")
                            self.ports_text.see("end")
                    except Exception:
                        pass
            
            if open_ports:
                self.ports_text.delete("1.0", "end")
                self.ports_text.insert("1.0", self._("open_ports_found"))
                for port in sorted(open_ports):
                    self.ports_text.insert("end", f"- {self._('port')} {port}\n")
            else:
                self.ports_text.delete("1.0", "end")
                self.ports_text.insert("1.0", self._("no_open_ports"))
            
            self.ports_text.configure(state="disabled")
        except Exception as e:
            self.ports_text.insert("end", f"\n\n{self._('error_ports').format(str(e))}")
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
                self.status_var.set(self._("error_reading_file").format(str(e)))
                return

            if self.is_ip(target):
                self.status_var.set(self._("subdomains_only_for_domains"))
                return
                
            domain = target.replace("www.", "") if target.startswith("www.") else target
            total_subdomains = len(subdomains)
            self.status_var.set(self._("checking_subdomains").format(total_subdomains))
            
            wildcard_ip = None
            try:
                random_sub = f"randomsub-{random.randint(100000, 999999)}.{domain}"
                wildcard_ip = socket.gethostbyname(random_sub)
                self.status_var.set(self._("wildcard_detected").format(wildcard_ip))
            except socket.gaierror:
                wildcard_ip = None
            
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
            
            USER_AGENTS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
            ]
            
            def check_subdomain(sub):
                full_domain = f"{sub}.{domain}"
                
                try:
                    ip = socket.gethostbyname(full_domain)
                    
                    if wildcard_ip and ip == wildcard_ip:
                        return None
                    
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
                            
                            if response.status_code < 400:
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
                        self.status_var.set(self._("scan_canceled"))
                        break
                    
                    processed_count += 1
                    
                    try:
                        result = future.result()
                        if result:
                            found_count += 1
                            self.subdomain_queue.put(result)
                            
                    except Exception as e:
                        pass
                    
                    if processed_count % 100 == 0:
                        self.status_var.set(
                            self._("subdomains_checked").format(
                                processed_count, 
                                total_subdomains, 
                                found_count
                            )
                        )
            
            if not self.scan_cancel:
                self.status_var.set(self._("subdomains_found").format(found_count))
                
        except Exception as e:
            self.status_var.set(self._("error_subdomains").format(str(e)))
    
    def check_web_paths(self, target, port):
        try:
            self.clear_paths_table()
            self.paths_data = []
            
            try:
                with open("paths.txt", "r") as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.status_var.set(self._("error_reading_file").format(str(e)))
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
            self.status_var.set(self._("checking_paths").format(total_urls))
            
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
                        self.status_var.set(self._("scan_canceled"))
                        break
                    
                    processed_count += 1
                    
                    try:
                        result = future.result()
                        if result:
                            found_count += 1
                            self.path_queue.put((result[0], result[1], result[2]))
                            
                    except Exception as e:
                        pass
                    
                    if processed_count % 100 == 0:
                        self.status_var.set(
                            self._("paths_checked").format(
                                processed_count,
                                total_urls,
                                found_count
                            )
                        )
            
            if not self.scan_cancel:
                self.status_var.set(self._("paths_found").format(found_count))
            
        except Exception as e:
            self.status_var.set(f"{self._('error')}: {str(e)}")

    def show_settings(self):
        """Показывает окно настроек"""
        self.settings_window = ctk.CTkToplevel(self)
        self.settings_window.title(self._("settings_title"))
        self.settings_window.geometry("500x350")
        self.settings_window.resizable(False, False)
        self.settings_window.transient(self)
        self.settings_window.grab_set()
        
        # Основной фрейм
        main_frame = ctk.CTkFrame(self.settings_window, corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Фрейм для настроек языка
        lang_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        lang_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        ctk.CTkLabel(
            lang_frame,
            text=self._("language_label"),
            font=("Arial", 14, "bold"),
            anchor="w"
        ).pack(fill="x", pady=(0, 10))
        
        # Создаем фрейм для кнопок языка
        lang_buttons_frame = ctk.CTkFrame(lang_frame, fg_color="transparent")
        lang_buttons_frame.pack(fill="x", padx=5, pady=5)
        
        # Словарь с языками и флагами
        languages = {
            "en": ("English", ""),
            "ru": ("Русский", "")
        }
        
        self.lang_var = tk.StringVar(value=self.current_language)
        
        # Создаем кнопки для каждого языка
        for lang_code, (lang_name, flag) in languages.items():
            btn = ctk.CTkButton(
                lang_buttons_frame,
                text=f"{flag} {lang_name}",
                command=lambda lc=lang_code: self.set_language(lc),
                width=120,
                height=40,
                font=("Arial", 13),
                fg_color="#3a7ebf" if self.current_language == lang_code else "#2a2d2e",
                hover_color="#1f538d",
                corner_radius=8
            )
            btn.pack(side="left", padx=5, pady=5)
        
        # Разделительная линия
        ctk.CTkFrame(
            main_frame, 
            height=2, 
            fg_color="#333333"
        ).pack(fill="x", padx=20, pady=10)
        
        # Фрейм для настроек масштабирования
        scale_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        scale_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        ctk.CTkLabel(
            scale_frame,
            text=self._("scale_label"),
            font=("Arial", 14, "bold"),
            anchor="w"
        ).pack(fill="x", pady=(0, 10))
        
        # Слайдер для масштабирования
        self.scale_var = tk.DoubleVar(value=SCALING_FACTOR * 100)
        
        # Обработчики для плавного изменения
        self.scale_slider = ctk.CTkSlider(
            scale_frame,
            variable=self.scale_var,
            from_=80,
            to=130,
            number_of_steps=50,
            command=self.on_scale_slider_move
        )
        self.scale_slider.pack(fill="x", padx=20, pady=10)
        
        # Метка с текущим значением
        self.scale_value_label = ctk.CTkLabel(
            scale_frame,
            text=f"{int(self.scale_var.get())}%",
            font=("Arial", 12)
        )
        self.scale_value_label.pack()
        
        # Фрейм для кнопок
        buttons_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=20, pady=(10, 0))
        
        # Кнопка сохранить
        save_btn = ctk.CTkButton(
            buttons_frame,
            text=self._("save_button"),
            command=self.save_settings,
            width=120,
            height=35,
            font=("Arial", 14),
            fg_color="#27ae60",
            hover_color="#2ecc71"
        )
        save_btn.pack(side="right", padx=(0, 10))
        
        # Кнопка закрытия
        close_btn = ctk.CTkButton(
            buttons_frame,
            text=self._("close_button"),
            command=self.settings_window.destroy,
            width=120,
            height=35,
            font=("Arial", 14),
            fg_color="#2c3e50",
            hover_color="#34495e"
        )
        close_btn.pack(side="right")
    
    def set_language(self, lang):
        """Устанавливает язык без сохранения"""
        self.current_language = lang
        # Обновляем кнопки языка в настройках
        for widget in self.settings_window.winfo_children():
            if isinstance(widget, ctk.CTkFrame):
                for subwidget in widget.winfo_children():
                    if isinstance(subwidget, ctk.CTkFrame):
                        for btn in subwidget.winfo_children():
                            if isinstance(btn, ctk.CTkButton):
                                if "English" in btn.cget("text") and lang == "en":
                                    btn.configure(fg_color="#3a7ebf")
                                elif "Русский" in btn.cget("text") and lang == "ru":
                                    btn.configure(fg_color="#3a7ebf")
                                else:
                                    btn.configure(fg_color="#2a2d2e")
    
    def on_scale_slider_move(self, value):
        """Обновляет значение при перемещении слайдера"""
        self.scale_value_label.configure(text=f"{int(float(value))}%")
    
    def save_settings(self):
        """Сохраняет настройки и закрывает окно"""
        # Сохраняем выбранный язык и масштаб
        language = self.current_language
        scaling = float(self.scale_var.get())
        
        # Сохраняем в файл
        self.settings_manager.save_settings(language, scaling)
        
        # Закрываем окно настроек
        self.settings_window.destroy()
        
        # Показываем сообщение о необходимости перезапуска
        self.status_var.set(self._("settings_saved"))
        
    def change_language(self, lang):
        """Изменяет язык интерфейса"""
        self.current_language = lang
        self.update_ui_texts()
    
    def update_ui_texts(self):
        """Обновляет все тексты в интерфейсе без пересоздания вкладок"""
        # Запоминаем текущую вкладку
        current_tab = self.tabview.get()
        
        # Обновляем заголовки вкладок
        self.tabview.configure(tab_names=[
            self._("geo_tab"),
            self._("paths_tab"),
            self._("subdomains_tab")
        ])
        
        # Обновляем другие тексты
        self.title(self._("app_title"))
        self.target_entry.configure(placeholder_text=self._("target_placeholder"))
        self.scan_btn.configure(text=self._("scan_button"))
        self.cancel_btn.configure(text=self._("cancel_button"))
        self.status_var.set(self._("ready_status"))
        
        # Обновляем заголовки таблиц
        self.paths_tree.heading("url", text=self._("url_column"))
        self.paths_tree.heading("status", text=self._("status_column"))
        self.paths_tree.heading("type", text=self._("type_column"))
        
        self.subdomains_tree.heading("subdomain", text=self._("subdomain_column"))
        self.subdomains_tree.heading("ip", text=self._("ip_column"))
        self.subdomains_tree.heading("status", text=self._("status_column"))
        self.subdomains_tree.heading("length", text=self._("length_column"))
        
        # Обновляем контекстные меню
        self.paths_context_menu.delete(0, "end")
        self.paths_context_menu.add_command(label=self._("copy_button"), command=lambda: self.copy_treeview_data(self.paths_tree))
        
        self.subdomains_context_menu.delete(0, "end")
        self.subdomains_context_menu.add_command(label=self._("copy_button"), command=lambda: self.copy_treeview_data(self.subdomains_tree))
        
        # Обновляем содержимое вкладки геолокации
        self.update_geo_tab_texts()
        
        # Восстанавливаем выбранную вкладку
        self.tabview.set(current_tab)
    
    def update_geo_tab_texts(self):
        """Обновляет тексты на вкладке геолокации"""
        # Обновляем заголовок
        for widget in self.tab_geo.winfo_children():
            if isinstance(widget, ctk.CTkFrame):
                for child in widget.winfo_children():
                    if isinstance(child, ctk.CTkLabel) and child.cget("text") == "Geo Location":
                        child.configure(text=self._("geo_location"))
                    elif isinstance(child, ctk.CTkLabel) and child.cget("text") == "Open Ports":
                        child.configure(text=self._("open_ports"))
        
        # Обновляем текст в гео-тексте
        if self.geo_text.get("1.0", "end-1c") != "":
            self.geo_text.configure(state="normal")
            self.geo_text.delete("1.0", "end")
            self.geo_text.insert("1.0", self._("geo_location") + " " + self._("ready_status"))
            self.geo_text.configure(state="disabled")
        
        # Обновляем текст в портах
        if self.ports_text.get("1.0", "end-1c") != "":
            self.ports_text.configure(state="normal")
            self.ports_text.delete("1.0", "end")
            self.ports_text.insert("1.0", self._("open_ports") + " " + self._("ready_status"))
            self.ports_text.configure(state="disabled")
    
    def show_info(self):
        """Показывает информационное окно о программе"""
        info_window = ctk.CTkToplevel(self)
        info_window.title(self._("info_title"))
        info_window.geometry("650x500")
        info_window.resizable(False, False)
        info_window.iconbitmap("iconw.ico")
        info_window.transient(self)
        info_window.grab_set()
        info_window.lift()
        info_window.focus_force()
        
        # Основной фрейм
        main_frame = ctk.CTkFrame(info_window, corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Фрейм для верхней части (картинка + заголовок)
        top_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        # Загружаем и размещаем картинку с прозрачностью
        try:
            pil_image = Image.open("logo.png").convert("RGBA")
            logo_img = ctk.CTkImage(
                light_image=pil_image,
                dark_image=pil_image,
                size=(100, 100)
            )
            img_label = ctk.CTkLabel(
                top_frame, 
                image=logo_img,
                text="",
                fg_color="transparent"
            )
            img_label.pack(side="left", padx=(0, 20))
        except Exception as e:
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
            text=self._("app_title"),
            font=("Arial", 24, "bold"),
            anchor="w"
        )
        title_label.pack(pady=(10, 0))
        
        subtitle_label = ctk.CTkLabel(
            title_frame,
            text=self._("info_subtitle"),
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
        info_label = ctk.CTkLabel(
            main_frame,
            text=self._("info_text"),
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
            text=self._("github_label"),
            font=("Arial", 14, "bold"),
            anchor="w"
        ).pack(side="left", padx=(0, 10))
        
        github_link = ctk.CTkLabel(
            github_frame,
            text=self._("github_link"),
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
            text=self._("close_button"),
            command=info_window.destroy,
            width=120,
            height=35,
            font=("Arial", 14),
            fg_color="#2c3e50",
            hover_color="#34495e"
        )
        close_btn.pack(pady=(10, 15))
    
    def open_github(self):
        """Открывает GitHub в браузере"""
        import webbrowser
        webbrowser.open(self._("github_link"))

if __name__ == "__main__":
    app = UltraSimpleScanner()
    app.mainloop()