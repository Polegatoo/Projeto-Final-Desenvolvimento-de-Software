# Projeto-Final-Desenvolvimento-de-Software
Projeto



import json
import requests
import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image
from kivy.uix.behaviors import ButtonBehavior
from kivy.graphics import Color, Rectangle
from kivy.uix.widget import Widget
from kivy.core.window import Window


# Variáveis de configuração da API do VirusTotal
api_key = "04f0e543d8608e67b3db7eaba7f015da71f857163975d6e436277cc10e16063e"
url_url = "https://www.virustotal.com/api/v3/urls"
url_file = "https://www.virustotal.com/api/v3/files"
CONFIG_FILE = 'app_config.json'


# Estilo de cor para a aplicação
Window.clearcolor = (0.1, 0.1, 0.2, 1)  # Fundo da janela

class ColoredBoxLayout(BoxLayout):
    def _init_(self, **kwargs):
        super()._init_(**kwargs)
        with self.canvas.before:
            Color(0.2, 0.2, 0.4, 1)  # Fundo do layout
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self._update_rect, pos=self._update_rect)

    def _update_rect(self, instance, value):
        self.rect.size = instance.size
        self.rect.pos = instance.pos


class SecurityApp(App):
    def build(self):
        self.title = "Intimação"

        # Layout principal
        main_layout = ColoredBoxLayout(orientation='vertical', padding=20, spacing=20)

        # Título
        title_label = Label(text="Intimação", font_size=30, bold=True, color=(1, 1, 1, 1))
        main_layout.add_widget(title_label)

        # Seção de Verificação de URL
        url_section = BoxLayout(orientation='vertical', spacing=10, padding=10)
        url_section.add_widget(Label(text="Verificar URL", font_size=20, bold=True, color=(1, 1, 0, 1)))

        self.url_input = TextInput(hint_text="Digite a URL para verificar", multiline=False, background_color=(1, 1, 1, 1))
        url_section.add_widget(self.url_input)

        check_url_button = Button(text="Verificar URL", background_color=(0, 0.5, 1, 1), color=(1, 1, 1, 1))
        check_url_button.bind(on_press=self.check_url)
        url_section.add_widget(check_url_button)

        self.url_result_label = Label(text="Resultado da URL aparecerá aqui", color=(1, 1, 1, 1))
        url_section.add_widget(self.url_result_label)

        main_layout.add_widget(url_section)

        # Seção de Verificação de Arquivo
        file_section = BoxLayout(orientation='vertical', spacing=10, padding=10)
        file_section.add_widget(Label(text="Verificar Arquivo", font_size=20, bold=True, color=(1, 1, 0, 1)))

        choose_file_button = Button(text="Escolher Arquivo", background_color=(0, 0.5, 1, 1), color=(1, 1, 1, 1))
        choose_file_button.bind(on_press=self.select_file)
        file_section.add_widget(choose_file_button)

        self.file_result_label = Label(text="Resultado do arquivo aparecerá aqui", color=(1, 1, 1, 1))
        file_section.add_widget(self.file_result_label)

        main_layout.add_widget(file_section)

        return main_layout

    def check_url(self, instance):
        """Conecta ao código base para verificar URLs"""
        url = self.url_input.text

        headers = {
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": "application/x-www-form-urlencoded"
        }
        payload = {"url": url}

        response = requests.post(url_url, data=payload, headers=headers)
        data = response.json()
        idd = data['data']['id']
        url_get = f"https://www.virustotal.com/api/v3/analyses/{idd}"

        headers2 = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        response = requests.get(url_get, headers=headers2)
        status = response.json()['data']['attributes']['stats']
        categorias = status.keys()
        resultado = str()
        for categoria in categorias:
            resultado = f'{resultado}        {categoria} - {status[categoria]}'

        self.url_result_label.text = resultado

    def select_file(self, instance):
        """Abre o seletor de arquivos para escolher um arquivo para verificação"""
        filechooser = FileChooserIconView()
        filechooser.bind(on_submit=self.on_file_selected)
        popup = Popup(title="Escolha o arquivo", content=filechooser, size_hint=(0.9, 0.9))
        popup.open()

    def on_file_selected(self, instance, selection, n):
        """Inicia a verificação do arquivo selecionado"""
        if selection:
            self.file_path = selection[0]
            self.file_result_label.text = "Verificando arquivo..."
            self.upload_file(self.file_path)

    def upload_file(self, file_path):
        """Envia o arquivo para o VirusTotal e verifica o status"""

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        file_name = os.path.basename(file_path)

        with open(file_name, "rb") as file:
            files = {"file": (file_name, file)}
            response = requests.post(url_file, headers=headers, files=files)

        if response.status_code == 200:
            data = response.json()
            idd = data['data']['id']
            url_get = f"https://www.virustotal.com/api/v3/analyses/{idd}"
            self.check_virustotal_report(idd)
        else:
            self.file_result_label.text = "Erro ao enviar o arquivo."

    def check_virustotal_report(self, idd):
        """Consulta o resultado da verificação no VirusTotal"""

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        url_get = f"https://www.virustotal.com/api/v3/analyses/{idd}"
        response = requests.get(url_get, headers=headers)
        if response.status_code == 200:

            status = response.json()['data']['attributes']['stats']
            categorias = status.keys()
            resultado = str()
            for categoria in categorias:
                resultado = f'{resultado}        {categoria} - {status[categoria]}'

            self.file_result_label.text = resultado
        else:
            self.file_result_label.text = "Erro ao obter o relatório."


if __name__ == '__main__':
    SecurityApp().run()
