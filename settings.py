
import configparser
import os
class SettingsManager:
    """Класс для управления настройками приложения"""
    def __init__(self, filename='settings.ini'):
        self.filename = filename
        self.config = configparser.ConfigParser()
        
    def load_settings(self):
        """Загружает настройки из файла"""
        settings = {
            'language': 'en',
            'scaling': 95.0
        }
        
        if os.path.exists(self.filename):
            self.config.read(self.filename)
            if 'Settings' in self.config:
                settings['language'] = self.config['Settings'].get('language', 'en')
                settings['scaling'] = float(self.config['Settings'].get('scaling', '95.0'))
        
        return settings
    
    def save_settings(self, language, scaling):
        """Сохраняет настройки в файл"""
        self.config['Settings'] = {
            'language': language,
            'scaling': str(scaling)
        }
        
        with open(self.filename, 'w') as configfile:
            self.config.write(configfile)