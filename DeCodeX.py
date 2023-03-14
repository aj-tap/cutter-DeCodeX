import json
import re
import subprocess
import cutter
from PySide2.QtCore import QObject, SIGNAL, Qt
from PySide2.QtGui import QIntValidator, QTextOption
from PySide2.QtWidgets import QAction, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget, QFrame, QScrollArea, \
    QTabWidget, QLineEdit, QHBoxLayout, QRadioButton, QTextEdit
import os
import logging


class DecodexWidget(cutter.CutterDockWidget):
    OPENAI_API_KEY = ""
    end_points = "/v1/completions"
    content_type = "application/json"
    OPENAI_MODEL = "text-davinci-003"
    MAX_TOKENS = 1024

    def __init__(self, parent, action):
        super(DecodexWidget, self).__init__(parent, action)
        self.setObjectName("DeCodeX")
        self.setWindowTitle("DeCodeX")
        self._label = QTabWidget(self)
        self.setWidget(self._label)
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tab4 = QWidget()
        self._label.addTab(self.tab1, "Binary Insights")
        self._label.addTab(self.tab2, "Code Annotator")
        self._label.addTab(self.tab3, "Codex Generator")
        self._label.addTab(self.tab4, "Settings")

        ################################################################################
        # TAB 1 (Binary Insights) #
        ################################################################################
        layout_tab1 = QVBoxLayout(self.tab1)
        label_overview = QLabel("Binary overview")  # title text
        # buttons for tab 1
        button_insights = QPushButton()
        button_insights.setText("Get Insights")
        insights_area = QScrollArea()
        insights_area.setWidgetResizable(True)
        self.display_insights = QTextEdit(insights_area)
        self.display_insights.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.display_insights.setWordWrapMode(QTextOption.WrapAnywhere)
        insights_area.setWidget(self.display_insights)
        # Button
        button_insights.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        button_insights.setMaximumHeight(50)
        button_insights.setMaximumWidth(200)
        # Add widgets to the tab 2
        layout_tab1.addWidget(label_overview)
        layout_tab1.addWidget(insights_area)
        layout_tab1.addWidget(button_insights)
        ################################################################################
        # TAB 2 (CODE ANNOTATOR) #
        ################################################################################
        layout_tab2 = QVBoxLayout(self.tab2)
        # Contents for tab 2
        # Upper window
        label_decompiler_code_area = QLabel("Ghidra Decompiler:")  # title text
        decompiler_code_area = QScrollArea()  # Area for decompiler output
        decompiler_code_area.setWidgetResizable(True)
        self.display_decompiler_code = QTextEdit(decompiler_code_area)  # The decompiler output
        self.display_decompiler_code.setReadOnly(True)
        self.display_decompiler_code.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.display_decompiler_code.setWordWrapMode(QTextOption.WrapAnywhere)
        decompiler_code_area.setWidget(self.display_decompiler_code)  # Set the widget inside the scroll area
        # Lower window
        label_code_annotation_area = QLabel("Code Annotation Output:")
        code_annotation_area = QScrollArea()
        code_annotation_area.setWidgetResizable(True)
        self.display_code_annotation = QTextEdit(code_annotation_area)  # The annotation output
        self.display_code_annotation.setReadOnly(True)
        self.display_code_annotation.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.display_code_annotation.setWordWrapMode(QTextOption.WrapAnywhere)
        code_annotation_area.setWidget(self.display_code_annotation)  # Set the widget inside the scroll area
        # Buttons in tab 2
        button_analyze = QPushButton()
        button_analyze.setText("Analyze")
        button_analyze.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        button_analyze.setMaximumHeight(50)
        button_analyze.setMaximumWidth(200)
        button_rename_func = QPushButton()
        button_rename_func.setText("Rename_Function")
        button_rename_func.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        button_rename_func.setMaximumHeight(50)
        button_rename_func.setMaximumWidth(200)
        # Add widgets to the tab 2
        layout_tab2.addWidget(label_decompiler_code_area)
        layout_tab2.addWidget(decompiler_code_area)
        layout_tab2.addWidget(label_code_annotation_area)
        layout_tab2.addWidget(code_annotation_area)
        layout_tab2.addWidget(button_analyze)
        layout_tab2.addWidget(button_rename_func)
        ################################################################################

        ################################################################################
        # TAB 3 (Codex Generator) #
        ################################################################################
        layout_tab3 = QVBoxLayout(self.tab3)
        # upper window
        label_jsdec = QLabel("Jsdec Decompiler: ")
        jsdec_pseudo_c_area = QScrollArea()  # Area for decompiler output
        jsdec_pseudo_c_area.setWidgetResizable(True)
        self.display_jsdec_code = QTextEdit(label_jsdec)  # The decompiler output
        self.display_jsdec_code.setReadOnly(True)
        self.display_jsdec_code.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.display_jsdec_code.setWordWrapMode(QTextOption.WrapAnywhere)
        jsdec_pseudo_c_area.setWidget(self.display_jsdec_code)
        # lower window
        label_codegen_output = QLabel("Code generated:")
        codegen_area = QScrollArea()  # Area for code output
        codegen_area.setWidgetResizable(True)
        self.display_codegen = QTextEdit(label_codegen_output)  # The code generated output
        self.display_codegen.setReadOnly(True)
        self.display_codegen.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.display_codegen.setWordWrapMode(QTextOption.WrapAnywhere)
        codegen_area.setWidget(self.display_codegen)
        # add buttons
        button_generate_code_c = QPushButton()
        button_generate_code_c.setText("Rewrite Code in C")
        button_generate_code_c.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        button_generate_code_c.setMaximumHeight(50)
        button_generate_code_c.setMaximumWidth(200)

        button_generate_code_python = QPushButton()
        button_generate_code_python.setText("Rewrite Code in Python")
        button_generate_code_python.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        button_generate_code_python.setMaximumHeight(50)
        button_generate_code_python.setMaximumWidth(200)

        # Add widgets to the tab 2
        layout_tab3.addWidget(label_jsdec)  # jsdec
        layout_tab3.addWidget(jsdec_pseudo_c_area)
        layout_tab3.addWidget(label_codegen_output)
        layout_tab3.addWidget(codegen_area)
        layout_tab3.addWidget(button_generate_code_c)
        layout_tab3.addWidget(button_generate_code_python)
        ################################################################################

        ################################################################################
        # TAB 4 (SETTINGS) #
        ################################################################################
        layout_tab4 = QVBoxLayout(self.tab4)
        label_settings = QLabel("Settings")
        # Model Selection
        label_model = QLabel("Model Selection (default=davinci):")
        self.text_davinci = QRadioButton("text-davinci-003")
        self.text_curie = QRadioButton("text-curie-001")
        self.text_babbage = QRadioButton("text-babbage-001")
        self.text_ada = QRadioButton("text-ada-001")
        model_layout = QVBoxLayout()
        model_layout.addWidget(label_model)
        model_layout.addWidget(self.text_davinci)
        model_layout.addWidget(self.text_curie)
        model_layout.addWidget(self.text_babbage)
        model_layout.addWidget(self.text_ada)
        self.text_davinci.setChecked(True)  # set default value
        # API keys input
        label_api_keys = QLabel("API keys:")
        self.api_keys_input = QLineEdit()
        api_keys_layout = QHBoxLayout()
        api_keys_layout.addWidget(label_api_keys)
        api_keys_layout.addWidget(self.api_keys_input)
        # Max Prompt input
        label_max_prompt = QLabel("Max Prompt (default=1024):")
        self.max_prompt_input = QLineEdit()
        self.max_prompt_input.setValidator(QIntValidator())
        max_prompt_layout = QHBoxLayout()
        max_prompt_layout.addWidget(label_max_prompt)
        max_prompt_layout.addWidget(self.max_prompt_input)
        # Buttons in tab 4
        button_settings = QPushButton()
        button_settings.setText("Save Settings")
        button_settings.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        button_settings.setMaximumHeight(50)
        button_settings.setMaximumWidth(200)
        # Add widgets to the tab 4
        layout_tab4.addWidget(label_settings)  # add title
        layout_tab4.addLayout(model_layout)  # add model selection
        layout_tab4.addWidget(label_api_keys)  # add api label
        layout_tab4.addWidget(self.api_keys_input)  # add api_input
        layout_tab4.addLayout(max_prompt_layout)  # add max prompt input
        layout_tab4.addLayout(max_prompt_layout)  # add max prompt input
        layout_tab4.addWidget(button_settings)  # add save button
        layout_tab4.addStretch(1)
        ################################################################################

        ################################################################################
        # Functions of the widgets
        cutter.core().seekChanged.connect(self.update_ghidra_decompiler)
        cutter.core().seekChanged.connect(self.update_jsdec_decompiler)
        button_insights.clicked.connect(self.openai_prompt_get_insights)
        button_generate_code_c.clicked.connect(self.openai_prompt_rewrite_code_c)
        button_generate_code_python.clicked.connect(self.openai_prompt_rewrite_code_python)
        button_analyze.clicked.connect(self.openai_prompt)
        button_rename_func.clicked.connect(self.openai_prompt_rename)
        button_settings.clicked.connect(lambda: self.save_settings(api_keys=self.api_keys_input.text(),
                                                                   max_prompt=self.max_prompt_input.text(),
                                                                   model_selection=self.get_selected_model()))
        self.show()

    def update_ghidra_decompiler(self):
        decompiled_code = cutter.cmd("pdg")
        cleaned_code = re.sub(r"\s*// WARNING:.*\n", "\n", decompiled_code)
        self.display_decompiler_code.setText(cleaned_code)

    def update_jsdec_decompiler(self):
        decompiled_code = cutter.cmd("pdd")
        if self.display_jsdec_code is not None:
            self.display_jsdec_code.setText(decompiled_code)
        else:
            print("Error: display_jsdec_code widget is None")

    def save_settings(self, api_keys, max_prompt, model_selection):
        cutter.message(f"Model Selection: {model_selection}")
        cutter.message(f"Max Prompt: {max_prompt}")
        cutter.message(f"API Keys: {api_keys}")
        self.OPENAI_API_KEY = str(api_keys)
        self.MAX_TOKENS = int(max_prompt)
        self.OPENAI_MODEL = str(model_selection)

    def get_selected_model(self):
        if self.text_davinci.isChecked():
            return "text-davinci-003"
        elif self.text_curie.isChecked():
            return "text-curie-001"
        elif self.text_babbage.isChecked():
            return "text-babbage-001"
        elif self.text_ada.isChecked():
            return "text-ada-001"
        else:
            return "text-davinci-003"

    def openai_prompt(self):
        decompiled_code = cutter.cmd("pdg")
        cleaned_code = re.sub(r"\s*// WARNING:.*\n", "\n", decompiled_code)
        prompt = """
                        Ghidra decompiled the C code below from a binary. 
                        ```
                        {decompiled_code}
                        ```
                       Could you please explain in detail what this code does? that a reverse engineer may find useful. 
                       Finally, suggest suitable names for this function with (), its parameters, and variables.
                        """.format(decompiled_code=decompiled_code)
        print(self.MAX_TOKENS)
        print(self.OPENAI_MODEL)
        print(self.OPENAI_API_KEY)
        response = openai_request(prompt, open_api_key=self.OPENAI_API_KEY, max_tokens=self.MAX_TOKENS,
                                  model=self.OPENAI_MODEL)
        print(response)
        res = response['choices'][0]['text'].strip()
        self.display_code_annotation.setText(str(res))

    def openai_prompt_rename(self):
        annotation_text = self.display_code_annotation.toPlainText()
        pattern = r"\b['\"]?([a-zA-Z0-9_]+)['\"]?\(\)"
        match = re.search(pattern, annotation_text)
        if match:
            function_name = match.group(1)
            cutter.cmd("afn {func}".format(func=function_name))
            print(function_name)
        else:
            print("No function name found in text:", annotation_text)
            cutter.cmd("afna")

    def openai_prompt_rewrite_code_c(self):
        print("making request")
        # decompiled_code = cutter.cmd("pdd")
        decompiled_code = cutter.cmd("pdg")  # ghidra
        cleaned_code = re.sub(r"\s*// WARNING:.*\n", "\n", decompiled_code)
        prompt = """// Rewrite this as a React component
        {decompiled_code}
        """.format(decompiled_code=cleaned_code)
        response = openai_request(prompt, open_api_key=self.OPENAI_API_KEY, max_tokens=self.MAX_TOKENS,
                                  model="davinci-codex")
        print(response)
        res = response['choices'][0]['text'].strip()
        self.display_codegen.setText(str(res))

    def openai_prompt_rewrite_code_python(self):
        print("making request")
        # decompiled_code = cutter.cmd("pdd")
        decompiled_code = cutter.cmd("pdg")  # ghidra
        cleaned_code = re.sub(r"\s*// WARNING:.*\n", "\n", decompiled_code)
        prompt = """# Convert this from C to Python
    # C version

    {decompiled_code}

    # End

    # Python version
            """.format(decompiled_code=cleaned_code)
        response = openai_request(prompt, open_api_key=self.OPENAI_API_KEY, max_tokens=self.MAX_TOKENS,
                                  model="davinci-codex")
        print(response)
        res = response['choices'][0]['text'].strip()
        self.display_codegen.setText(str(res))

    def openai_prompt_get_insights(self):
        print("making request")
        info = self.get_basic_binary_info()
        prompt = """
        Identify anomalies and provide insights that will aid in reverse engineering.
        {info}
        """.format(info=info)
        response = openai_request(prompt, open_api_key=self.OPENAI_API_KEY, max_tokens=self.MAX_TOKENS,
                                  model=self.OPENAI_MODEL)
        res = response['choices'][0]['text'].strip()
        print(res)
        self.display_insights.setText(res)

    def get_basic_binary_info(self):
        file = cutter.cmd('i')
        libraries = cutter.cmd('ilq')
        # list_imports = cutter.cmd('iiq')
        # list_exports = cutter.cmd('iEq')
        # top_strings = cutter.cmd('izQ')  # 12 strings
        binary_headers = cutter.cmd('izQ')
        list_symbols = cutter.cmd('isQ')
        print(file + libraries + list_symbols)
        return file + libraries + list_symbols + binary_headers


class MyCutterPlugin(cutter.CutterPlugin):
    name = "DeCodex"
    description = "This plugin perform code annotation and perform binary insights using open ai"
    version = "1.0"
    author = "aj-tap"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("DeCodex", main)
        action.setCheckable(True)
        widget = DecodexWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass


def create_cutter_plugin():
    return MyCutterPlugin()


def send_https_request(address, path, data, headers):
    try:
        url = "https://{address}{path}".format(address=address, path=path)
        json_req_data = json.dumps(data)
        curl_command = ['curl', '-sS', '-X', 'POST', '-d', json_req_data, url]
        for key, value in headers.items():
            curl_command += ['-H', '{key}: {value}'.format(key=key, value=value)]
        curl_output = subprocess.check_output(curl_command)
        json_data = curl_output.decode('utf-8')
        try:
            data = json.loads(json_data)
            return data
        except ValueError:
            logging.error("Could not parse JSON response from OpenAI!")
            logging.debug(json_data)
            return None
    except Exception as e:
        logging.error("Error sending HTTPS request: {e}".format(e=e))
        return None


def openai_request(prompt, open_api_key, temperature=0.19, max_tokens=500, model="text-davinci-003"):
    data = {
        "model": model,
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature
    }
    # The URL is "https://api.openai.com/v1/completions"
    host = "api.openai.com"
    path = "/v1/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer {openai_api_key}".format(openai_api_key=open_api_key),
    }
    json_data = json.dumps(data)
    command = ["curl", "-X", "POST", "-H", f"Content-Type: application/json", "-H",
               f"Authorization: Bearer {open_api_key}", "--data", json_data, f"https://{host}{path}"]
    response = subprocess.check_output(command, stderr=subprocess.PIPE)
    try:
        data = json.loads(response)
        return data
    except ValueError:
        logging.error("Could not parse JSON response from OpenAI!")
        logging.debug(response)
        return None
