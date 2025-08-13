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
import asyncio
import concurrent.futures
from random import choice
from functools import partial

# Настройка внешнего вида
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class UltraSimpleScanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Основные настройки окна
        self.title("WebSec Scanner")
        self.geometry("1100x750")
        self.minsize(900, 650)
        
        # Создаем сетку
        self.grid_rowconfigure(0, weight=0)  # Верхняя панель
        self.grid_rowconfigure(1, weight=0)  # Анимация подключения
        self.grid_rowconfigure(2, weight=1)   # Основной контент
        self.grid_columnconfigure(0, weight=3)  # Левая часть
        self.grid_columnconfigure(1, weight=2)  # Правая часть (карта)
        
        # Верхняя панель (ввод и кнопка)
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
        
        # Кнопка отмены
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
        
        # Панель анимации подключения (компактная)
        self.connection_frame = ctk.CTkFrame(self, height=25, corner_radius=10, fg_color="#1a1a1a")
        self.connection_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        self.connection_frame.grid_propagate(False)
        self.grid_rowconfigure(1, weight=0, minsize=25)
        
        # Холст для анимации
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
        
        # Левая панель (информация)
        self.info_frame = ctk.CTkFrame(self, corner_radius=10)
        self.info_frame.grid(row=2, column=0, padx=(20, 10), pady=(0, 20), sticky="nsew")
        self.info_frame.grid_rowconfigure(0, weight=1)
        self.info_frame.grid_columnconfigure(0, weight=1)
        
        # Правая панель (карта)
        self.map_frame = ctk.CTkFrame(self, corner_radius=10)
        self.map_frame.grid(row=2, column=1, padx=(10, 20), pady=(0, 20), sticky="nsew")
        self.map_frame.grid_rowconfigure(0, weight=1)
        self.map_frame.grid_columnconfigure(0, weight=1)
        
        # Создаем карту
        self.map_widget = tkintermapview.TkinterMapView(
            self.map_frame, 
            corner_radius=8
        )
        self.map_widget.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.map_widget.set_position(55.7558, 37.6173)  # Москва по умолчанию
        self.map_widget.set_zoom(3)
        
        # Контейнер для информации
        self.tabview = ctk.CTkTabview(self.info_frame, corner_radius=8)
        self.tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.tabview.grid_columnconfigure(0, weight=1)

        # Создаем вкладки
        self.tab_geo = self.tabview.add("Геолокация и порты")
        self.tab_paths = self.tabview.add("Веб-пути")

        # Настраиваем каждую вкладку
        self.tabview.set("Геолокация и порты")  # Устанавливаем активной первую вкладку

        # Вкладка геолокации и портов
        self.tab_geo.grid_columnconfigure(0, weight=1)
        self.tab_geo.grid_rowconfigure(0, weight=0)
        self.tab_geo.grid_rowconfigure(1, weight=1)

        # Секция геолокации
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

        # Вкладка веб-путей
        self.tab_paths.grid_columnconfigure(0, weight=1)
        self.tab_paths.grid_rowconfigure(0, weight=1)

        ctk.CTkLabel(
            self.tab_paths, 
            text="Доступные веб-пути",
            font=("Arial", 14, "bold"),
            anchor="w"
        ).pack(fill="x", padx=15, pady=(10, 5))

        self.paths_text = ctk.CTkTextbox(
            self.tab_paths, 
            wrap="word",
            font=("Arial", 13),
            activate_scrollbars=True
        )
        self.paths_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.paths_text.insert("1.0", "Доступные пути будут показаны здесь")
        self.paths_text.configure(state="disabled")

        
        # Статус бар
        self.status_var = tk.StringVar(value="Готов к сканированию")
        self.status_bar = ctk.CTkLabel(
            self, 
            textvariable=self.status_var,
            anchor="w",
            font=("Arial", 12),
            fg_color="#333333",
            corner_radius=0,
            padx=20
        )
        self.status_bar.grid(row=3, column=0, columnspan=2, sticky="ew")
        
        # Переменные
        self.scan_active = False
        self.scan_cancel = False
        self.marker = None
        self.scan_stage = 0
        self.scan_thread = None
        
        # Определяем наш IP
        self.get_my_ip()
    
    def get_my_ip(self):
        """Получаем наш публичный IP"""
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
        """Запускаем анимацию подключения"""
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        self.animation_pos = 0
        self.bit_particles = []
        self.animation_complete = False
        self.animate_connection()
    
    def animate_connection(self):
        """Анимируем подключение"""
        self.canvas.delete("all")
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        if width < 100 or height < 20:
            self.animation_id = self.after(50, self.animate_connection)
            return
        
        # Рисуем линию подключения
        self.canvas.create_line(50, height//2, width-50, height//2, fill="#333", width=2, dash=(4, 2))
        
        # Отображаем IP
        self.canvas.create_text(10, height//2-10, text=f"{self.my_ip}", 
                              anchor="w", fill="#3498db", font=("Arial", 12))
        
        # Отображаем IP сервера (с эффектом раскрытия)
        server_ip_display = self.get_revealed_ip()
        self.canvas.create_text(width-10, height//2-10, text=f"{server_ip_display}", 
                              anchor="e", fill="#e74c3c", font=("Arial", 12))
        
        # Рисуем точки подключения
        self.canvas.create_oval(45, height//2-3, 55, height//2+3, fill="#3498db", outline="")
        self.canvas.create_oval(width-55, height//2-3, width-45, height//2+3, fill="#e74c3c", outline="")
        
        # Генерируем новые "биты данных" только если сканирование активно
        if self.scan_active and random.random() < 0.3:
            self.bit_particles.append({
                'pos': 0,
                'size': random.randint(3, 4),
                'speed': random.uniform(0.01, 0.02),
                'color': self.random_green_color()
            })
        
        # Анимируем "биты данных"
        particles_to_remove = []
        for bit in self.bit_particles:
            # Рассчитываем позицию
            x = 50 + (width - 100) * bit['pos']
            
            # Рисуем частицу
            self.canvas.create_oval(x-bit['size'], height//2-bit['size'], 
                                  x+bit['size'], height//2+bit['size'], 
                                  fill=bit['color'], outline="")
            
            # Обновляем позицию
            bit['pos'] += bit['speed']
            
            # Если частица достигла конца, помечаем для удаления
            if bit['pos'] > 1:
                particles_to_remove.append(bit)
        
        # Удаляем частицы, достигшие конца
        for bit in particles_to_remove:
            self.bit_particles.remove(bit)
        
        # Обновляем раскрытие IP
        if self.reveal_progress < self.reveal_steps:
            self.reveal_progress += 0.1
        
        # Если сканирование завершено и нет активных частиц
        if not self.scan_active and not self.bit_particles and not self.animation_complete:
            # Запускаем финальную анимацию
            self.animation_complete = True
            status_text = "✓ Сканирование отменено" if self.scan_cancel else "✓ Сканирование завершено"
            self.canvas.create_text(width//2, height//2+10, text=status_text, 
                                  fill="#2ecc71", font=("Arial", 10, "bold"))
        
        # Продолжаем анимацию, если нужно
        if not self.animation_complete:
            self.animation_id = self.after(30, self.animate_connection)
    
    def random_green_color(self):
        """Генерирует случайный зеленый цвет"""
        r = random.randint(0, 50)
        g = random.randint(200, 255)
        b = random.randint(0, 50)
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def get_revealed_ip(self):
        """Возвращает IP сервера с эффектом постепенного раскрытия"""
        if self.reveal_progress >= self.reveal_steps:
            return self.server_ip
        
        # Определяем сколько символов раскрыть
        total_chars = len(self.server_ip)
        revealed_chars = min(total_chars, int(total_chars * (self.reveal_progress / self.reveal_steps)))
        
        # Формируем строку с частично раскрытым IP
        revealed = self.server_ip[:revealed_chars]
        hidden = '*' * (total_chars - revealed_chars)
        return revealed + hidden
    def start_scan(self, event=None):
        port = 80
        if self.scan_active:
            return


        target = self.target_entry.get().strip()
        if ":" in target: target, port = target.split(":")
        if not target:
            self.status_var.set("Ошибка: введите домен или IP")
            return
        
        # Валидация ввода
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
        
        # Определяем IP сервера
        try:
            self.server_ip = socket.gethostbyname(target)
        except:
            self.server_ip = "Неизвестен"
        
        # Запускаем анимацию
        self.start_animation()
        
        # Запуск в отдельном потоке
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target, port), daemon=True)
        self.scan_thread.start()
    
    def cancel_scan(self):
        """Отмена текущего сканирования"""
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
        # Очистка текстовых полей
        for widget in [self.geo_text, self.ports_text, self.paths_text]:
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.configure(state="disabled")
        
        # Очистка карты
        if self.marker:
            self.map_widget.delete(self.marker)
            self.marker = None
        
        # Сброс карты
        self.map_widget.set_position(55.7558, 37.6173)
        self.map_widget.set_zoom(3)
    
    def run_scan(self, target, port):
        try:
            # Этап 1: Геолокация
            self.status_var.set("Определение геолокации...")
            self.get_geolocation(target)
            if self.scan_cancel: return
            self.reveal_progress = 5  # Раскрываем часть IP
            
            # Этап 2: Сканирование портов
            self.status_var.set("Сканирование портов...")
            self.scan_ports(target)
            if self.scan_cancel: return
            self.reveal_progress = 10  # Раскрываем больше IP
            
            # Этап 3: Проверка путей
            self.status_var.set("Проверка веб-путей...")
            self.check_web_paths(target, port)
            if self.scan_cancel: return
            self.reveal_progress = 15  # Полностью раскрываем IP
            
            # Завершаем сканирование
            self.status_var.set("Сканирование завершено!")
            
        except Exception as e:
            self.status_var.set(f"Ошибка: {str(e)}")
        finally:
            # Даем время для завершения анимации
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
            
            # Очищаем предыдущие маркеры и линии
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
            
            # Если есть оба маркера, рисуем линию между ними
            if len(self.map_markers) == 2:
                self.connection_line = self.map_widget.set_path([
                    (my_lat, my_lon),
                    (server_lat, server_lon)
                ], color="#2ecc71", width=2)
            
            # Устанавливаем оптимальный масштаб для отображения обоих точек
            if server_lat and server_lon and my_lat and my_lon:
                # Рассчитываем среднюю точку
                avg_lat = (server_lat + my_lat) / 2
                avg_lon = (server_lon + my_lon) / 2
                
                # Рассчитываем расстояние между точками
                distance = self.calculate_distance(server_lat, server_lon, my_lat, my_lon)
                
                # Устанавливаем зум в зависимости от расстояния
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
        """Рассчитывает расстояние между двумя точками в километрах (формула гаверсинусов)"""
        R = 6371  # Радиус Земли в км
        
        dLat = math.radians(lat2 - lat1)
        dLon = math.radians(lon2 - lon1)
        
        a = (math.sin(dLat/2) * math.sin(dLat/2) +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dLon/2) * math.sin(dLon/2))
        
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c
    
    def calculate_zoom_level(self, distance_km):
        """Определяет оптимальный уровень зума на основе расстояния"""
        if distance_km < 1:
            return 14
        elif distance_km < 5:
            return 12
        elif distance_km < 20:
            return 10
        elif distance_km < 50:
            return 8
        elif distance_km < 200:
            return 6
        elif distance_km < 500:
            return 5
        elif distance_km < 1000:
            return 4
        else:
            return 3
    
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
            
            # Быстрое сканирование только основных портов
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
            
            # Используем ThreadPoolExecutor для параллельного сканирования
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
            
            # Форматируем результат
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
    
    def check_web_paths(self, target, port):
        try:
            # Очистка текстового поля
            self.paths_text.configure(state="normal")
            self.paths_text.delete("1.0", "end")
            self.paths_text.insert("end", "Сканирование начато...\n")
            self.paths_text.see("end")
            
            # Загрузка путей
            try:
                with open("paths.txt", "r") as f:
                    paths = [line.strip() for line in f if line.strip()]
                print(f"Загружено {len(paths)} путей из файла")
            except Exception as e:
                self.paths_text.insert("end", f"Ошибка чтения файла: {str(e)}\n")
                print(f"Ошибка чтения файла: {str(e)}")
                return

            # Улучшенные User-Agents
            USER_AGENTS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"
            ]
            
            found_paths = []
            protocols = ["http", "https"]
            results_to_display = []
            last_update_time = time.time()
            processed_count = 0
            found_count = 0
            
            # Формируем URL правильно
            urls = []
            for protocol in protocols:
                if port != 80:
                    base_url = f"{protocol}://{target}:{port}"
                else:
                    base_url = f"{protocol}://{target}"
                urls.append(base_url)  # Корневой путь
                
                for path in paths:
                    # Формируем путь с правильным форматом
                    if path.startswith("/"):
                        url = base_url + path
                    else:
                        url = base_url + "/" + path
                    urls.append(url)
            
            total_urls = len(urls)
            self.paths_text.insert("end", f"Проверяем {total_urls} путей...\n")
            self.paths_text.see("end")
            print(f"Начинаем сканирование: {total_urls} URL")
            print(f"Пример URL: {urls[0] if urls else 'N/A'}")
            
            # Функция для проверки одного URL
            def check_single_url(url):
                nonlocal found_count
                try:
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    
                    # Используем контекстный менеджер для каждого запроса
                    with httpx.Client(follow_redirects=True, timeout=5, verify=False) as client:
                        response = client.get(url, headers=headers)
                        
                        # Расширенные условия успеха
                        if 200 <= response.status_code < 400:
                            return url, response.status_code
                        # Для некоторых сайтов 403 может быть успехом
                        elif response.status_code == 403 and len(response.text) > 100:
                            return url, response.status_code
                        # Обработка редиректов
                        elif 300 <= response.status_code < 400:
                            location = response.headers.get('Location', '')
                            if location and not location.startswith(('http://', 'https://')):
                                location = url + location
                            return f"Redirect: {url} -> {location}", response.status_code
                except httpx.TimeoutException:
                    return None
                except httpx.ConnectError:
                    return None
                except Exception as e:
                    # Логируем только необычные ошибки
                    if not isinstance(e, (httpx.ReadTimeout, httpx.PoolTimeout)):
                        return f"Error: {url} - {str(e)}", 0
                return None
            
            # Используем ThreadPoolExecutor с ограниченным количеством потоков
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_url = {executor.submit(check_single_url, url): url for url in urls}
                
                for future in concurrent.futures.as_completed(future_to_url):
                    if self.scan_cancel:
                        # Отменяем все оставшиеся задачи
                        for f in future_to_url:
                            f.cancel()
                        self.paths_text.insert("end", "\nСканирование отменено\n")
                        break
                    
                    processed_count += 1
                    url = future_to_url[future]
                    
                    # Выводим прогресс в консоль каждые 500 URL
                    if processed_count % 500 == 0 or processed_count == total_urls:
                        progress = (processed_count / total_urls) * 100
                        print(f"Прогресс: {processed_count}/{total_urls} ({progress:.1f}%)")
                        print(f"Найдено: {found_count} путей")
                    
                    try:
                        result = future.result()
                        if result:
                            # Обрабатываем разные типы результатов
                            if isinstance(result, tuple):
                                result_url, status_code = result
                                
                                # Для редиректов
                                if isinstance(result_url, str) and result_url.startswith("Redirect:"):
                                    results_to_display.append(f"{status_code}: {result_url}\n")
                                    found_count += 1
                                # Для обычных URL
                                else:
                                    found_paths.append(result_url)
                                    found_count += 1
                                    display_url = result_url.replace(target, "***")
                                    results_to_display.append(f"{status_code}: {display_url}\n")
                            # Обработка ошибок
                            elif isinstance(result, str) and result.startswith("Error:"):
                                results_to_display.append(f"{result}\n")
                    except Exception as e:
                        results_to_display.append(f"Ошибка обработки: {url} - {str(e)}\n")
                    
                    # Обновляем GUI только каждые 0.5 секунды или при 50+ результатах
                    current_time = time.time()
                    if (current_time - last_update_time > 1 or 
                        len(results_to_display) >= 100 or 
                        processed_count == total_urls):
                        
                        if results_to_display:
                            self.paths_text.configure(state="normal")
                            for res in results_to_display:
                                self.paths_text.insert("end", res)
                            self.paths_text.see("end")
                            self.paths_text.configure(state="disabled")
                            results_to_display = []
                        
                        last_update_time = current_time
            
            # Финал сканирования
            self.paths_text.configure(state="normal")
            if found_paths:
                self.paths_text.insert("end", f"\nНайдено {found_count} доступных путей\n")
            else:
                self.paths_text.insert("end", "Доступные пути не найдены\n")
                print("Доступные пути не найдены. Проверьте целевой домен и файл paths.txt")
            
            if not self.scan_cancel:
                self.paths_text.insert("end", "Сканирование завершено\n")
            
            print(f"Сканирование завершено. Проверено: {processed_count}/{total_urls}, Найдено: {found_count} путей")
            
        except Exception as e:
            self.paths_text.insert("end", f"Ошибка: {str(e)}\n")
            print(f"Критическая ошибка: {str(e)}")
        finally:
            self.paths_text.configure(state="disabled")
            self.paths_text.see("end")
if __name__ == "__main__":
    app = UltraSimpleScanner()
    app.mainloop()