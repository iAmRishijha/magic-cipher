import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QTextEdit, QPushButton, QFileDialog, QWidget
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class MagicCipherDecryptionTool(QMainWindow):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Magic Cipher Decryption Tool')
        self.setGeometry(100, 100, 800, 600)

        self.ciphertext_label = QLabel('Enter Ciphertext:', self)
        self.ciphertext_input = QTextEdit(self)

        self.key_label = QLabel('Enter Secret Key (16, 24, or 32 bytes):', self)
        self.key_input = QTextEdit(self)

        self.iv_label = QLabel('Enter Initialization Vector (IV - 16 bytes):', self)
        self.iv_input = QTextEdit(self)

        self.decrypt_button = QPushButton('Decrypt', self)
        self.decrypt_button.clicked.connect(self.decrypt_data)

        self.result_label = QLabel('Decrypted Data:', self)
        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(self.ciphertext_label)
        layout.addWidget(self.ciphertext_input)
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)
        layout.addWidget(self.iv_label)
        layout.addWidget(self.iv_input)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_text)

        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def decrypt_data(self):
        ciphertext = bytes.fromhex(self.ciphertext_input.toPlainText().strip())
        key = self.key_input.toPlainText().encode('utf-8')
        iv = self.iv_input.toPlainText().encode('utf-8')

        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)

            # Use custom PKCS7 unpadding
            unpadded_data = self.pkcs7_unpad(decrypted_data)

            self.result_text.setPlainText(unpadded_data.decode('utf-8'))
        except Exception as e:
            self.result_text.setPlainText(f"Error: {str(e)}")

    
    def pkcs7_unpad(self, data):
        pad_byte = data[-1]
        pad_size = int(pad_byte)
        return data[:-pad_size]

def main():
    app = QApplication(sys.argv)
    window = MagicCipherDecryptionTool()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
