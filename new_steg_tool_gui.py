from Cryptodome import Random
from Cryptodome.Random import random
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import hashlib
import hmac
import time
import sys
import os
import getpass
from PyQt5.QtWidgets import (QWidget, QMainWindow, QSizePolicy,
	QGridLayout, QHBoxLayout, QVBoxLayout, QPushButton, QApplication,
	qApp, QAction, QFileDialog, QInputDialog, QTabWidget, QTableWidget, QTableWidgetItem, QLabel,
	QComboBox, QDialog, QLineEdit, QMessageBox, QGroupBox, QRadioButton, QScrollArea, QCheckBox, QTextEdit)
from PyQt5.QtGui import QColor, QIntValidator, QIcon
from PyQt5.QtCore import Qt


PROGRAM_NAME = "NewStegToolGUI v1.0"
MINIMUM_PASSWORD_SIZE_ENCRYPTION = 8

SCRYPT_R = 8
SCRYPT_N = 2**17
SCRYPT_P = 20
SHA512_ITERS = 4000000

SCRYPT_MAXMEM = 128 * SCRYPT_R * (SCRYPT_N + SCRYPT_P + 2)
MIN_PADSIZE_NONSTEG = 0
MAX_PADSIZE_NONSTEG = 262144 * 4
TOTAL_OVERHEAD_BEGINNING = 704
TOTAL_OVERHEAD_END = 320
TOTAL_OVERHEAD_LENGTH = TOTAL_OVERHEAD_BEGINNING + TOTAL_OVERHEAD_END

print(SCRYPT_MAXMEM//1024, "KB FOR SCRYPT")

SIZE_POLICY_FILE_NAMES = QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Preferred,)
SIZE_POLICY_FIXED_LABEL = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred,)

HMAC1_DISSUASIVE_TEXT = ("*****HMAC1 NOT OK******\n"
						"******WRONG PASSWORD/DAMAGED FILE*****\n"
						"You could try to decrypt this anyways, at your own risk "
						"Do you want to continue (NOT RECOMMENDED)")

HMAC2_DISSUASIVE_TEXT = ("*****HMAC2 NOT OK******\n"
						"*****FILE INTEGRITY NOT GUARANTEED*****\n"
						"You could try to decrypt this anyways, at your own risk\n"
						"Do you want to continue (NOT RECOMMENDED)")

FINAL_HMAC_DISSUASIVE_TEXT = ("*****FINAL HMAC NOT OK*****\n"
							"*****POSSIBLE KEYSLOT GUESSING ATTACK*****\n"
							"IF YOU CONTINUE AND HMAC2 IS OK, ANOTHER KEYSLOT "
							"WAS POSSIBLY DAMAGED ON PURPOSE BY AN ATTACKER "
							"TO FIND OUT IF YOU WERE USING THAT SLOT\n"
							"Do you want to continue (NOT RECOMMENDED)")

def read_file_to_bytearray(file_name):
	try:
		test_file = open(file_name,'rb')
		output = bytearray(test_file.read())
		test_file.close()
		return output
	except FileNotFoundError:
		return False
		
def read_file_length(file_name):
	try:
		test_file = open(file_name,'rb')
		output = len(test_file.read())
		test_file.close()
		return output
	except FileNotFoundError:
		return False
		
def is_file_accessible(file_name):
	try:
		test_file = open(file_name,'r')
		test_file.close()
		return True
	except:
		return False
		
def write_file_from_bytearray(file_name,input_bytearray):
	if input_bytearray != None:
		test_file = open(file_name,'wb')
		test_file.write(input_bytearray)
		test_file.close()
	return True

def do_xor_on_bytes(bs1,bs2):
	l1 = len(bs1)
	bi1, bi2 = int.from_bytes(bs1, byteorder='little'), int.from_bytes(bs2, byteorder='little')
	x = bi1 ^ bi2
	return x.to_bytes(l1, byteorder='little')

def generate_keyslot(passphrase):
	encoded_passphrase = passphrase.encode()
	# ~ print(encoded_passphrase)
	salt_to_use = Random.get_random_bytes(64)
	generated_key_scrypt = hashlib.scrypt(encoded_passphrase, salt=salt_to_use, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM)
	generated_key_keccak = hashlib.pbkdf2_hmac('sha512', encoded_passphrase, salt_to_use, SHA512_ITERS)
	return salt_to_use, generated_key_scrypt+generated_key_keccak
	
def read_keyslot(salt, passphrase):
	encoded_passphrase = passphrase.encode()
	# ~ print(encoded_passphrase)
	salt_to_use = salt
	generated_key_scrypt = hashlib.scrypt(encoded_passphrase, salt=salt_to_use, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM)
	generated_key_keccak = hashlib.pbkdf2_hmac('sha512', encoded_passphrase, salt_to_use, SHA512_ITERS)
	return generated_key_scrypt+generated_key_keccak
	
def generate_keys_from_master(master_key):
	AES256_KEY = hashlib.sha256(hashlib.sha3_512(master_key).digest()).digest()
	HMAC1_KEY = hashlib.sha256(hashlib.sha3_384(master_key+master_key).digest()).digest()
	HMAC2_KEY = hashlib.sha256(hashlib.sha3_256(master_key+master_key+master_key).digest()).digest()
	ECK_XOR = hashlib.sha3_256(hashlib.sha1(master_key).digest()).digest()
	return [AES256_KEY, HMAC1_KEY, HMAC2_KEY, ECK_XOR]
	# ~ print(generated_key_keccak)
	# ~ print(time.time()-t1)

def calculate_hmac1_hmac2(input_data, key):
	return hmac.new(key,msg=input_data,digestmod=hashlib.sha3_512).digest()


class AES256_CTR(object):
	def __init__(self, key):
		self.key = key
		self.counter = Counter.new(128)
		if len(self.key) != 32:
			print("AES KEY ERROR, CIPHER INSECURE")
			print("REPORT THIS ERROR")
			print("YOU SHOULD ****NEVER**** SEE THIS")
			quit()
		self.aes_cipher = AES.new(self.key, AES.MODE_CTR, counter=self.counter)
	def encrypt(self, data):
		return self.aes_cipher.encrypt(bytes(data))

class MAIN_ENCRYPT(object):
	def __init__(self, qtobj=None):
		self.qtobj = qtobj
		self.using_gui = True if self.qtobj != None else False
		self.steg_size = -1
		self.padding_init = False
		self.padding_sizes = [0,0,0,0,0]
		self.inner_lengths = [
		[None, None],
		[None, None],
		[None, None],
		[None, None]]
		self.encryption_ready = False
		self.encrypted_data = None
		self.password_init = False
		# paddings are:
		# PADDING 1 FILE 1 P2 F2 P3 F3 P4 F4 P5
	def reset(self):
		pass
	def init_steg(self, steg_size):
		self.steg_size = steg_size
	def set_input_files(self, file_location_list):
		if self.using_gui:
			self.qtobj.write_to_status_bar("Setting input files")
		self.files_ok = [False, False, False, False]
		self.files_read = [False, False, False, False]
		self.files_length = [0,0,0,0]
		self.total_file_size = 0
		for i in range(0,4):
			if file_location_list[i] != False and is_file_accessible(file_location_list[i]) == True:
				try:
					if self.using_gui:
						self.qtobj.write_to_status_bar("Reading file "+file_location_list[i])
					self.files_read[i] = read_file_to_bytearray(file_location_list[i])
					self.files_length[i] = len(self.files_read[i])
					self.total_file_size += self.files_length[i]
					self.files_ok[i] = True
				except:
					if self.using_gui:
						self.qtobj.show_error_message("File Error", "File "+file_location_list+ "not OK, skipping!")
						QApplication.processEvents()
					self_files_ok[i] = False
			elif file_location_list[i] == False:
				return False
				pass
		return True
	def calculate_paddings_and_lengths(self):
		self.padding_init = True
		if self.steg_size == -1:
			for i in range(0, len(self.padding_sizes)):
				self.padding_sizes[i] = random.randint(MIN_PADSIZE_NONSTEG, MAX_PADSIZE_NONSTEG)
		else:
			remaining_size = (self.steg_size - self.total_file_size - TOTAL_OVERHEAD_LENGTH)
			#print(remaining_size, "remaining size")
			for i in range(0, len(self.padding_sizes)-1):
				self.padding_sizes[i] = random.randint(0, remaining_size//(len(self.padding_sizes)-i-1))
				remaining_size -= self.padding_sizes[i]
				#print(remaining_size, "remaining size")
			self.padding_sizes[-1] = remaining_size
			
			#The last padding size must cover all the remaining space!.
			#That means, its size will be the requested steg size, 
			#less the actual encrypted file sizes, less the already calculated padding,
			#less the total overhead.
			print(sum(self.padding_sizes), "sum of paddings")
			print(sum(self.padding_sizes) + self.total_file_size + TOTAL_OVERHEAD_LENGTH, "total new file size")
			print(self.steg_size, "requested steg")
		self.inner_lengths = [
		[TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0], TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]],
		[TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]+self.padding_sizes[1], TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]+self.padding_sizes[1]+self.files_length[1]],
		[TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]+self.padding_sizes[1]+self.files_length[1]+self.padding_sizes[2], TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]+self.padding_sizes[1]+self.files_length[1]+self.padding_sizes[2]+self.files_length[2]],
		[TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]+self.padding_sizes[1]+self.files_length[1]+self.padding_sizes[2]+self.files_length[2]+self.padding_sizes[3], TOTAL_OVERHEAD_BEGINNING+self.padding_sizes[0]+self.files_length[0]+self.padding_sizes[1]+self.files_length[1]+self.padding_sizes[2]+self.files_length[2]+self.padding_sizes[3]+self.files_length[3]]]
	def input_passwords(self, password_list):
		self.password_list = password_list
		self.password_init = True
	def generate_encrypted_data(self):
		#generating keys/randomness
		generated_keyslots = [None, None, None, None]
		generated_keyslots_keys_from_master = [None, None, None, None]
		generated_final_hmac_key = Random.get_random_bytes(32)
		cipher_slots = [None, None, None, None]
		calculated_hmac1 = [None, None, None, None]
		calculated_hmac2 = [None, None, None, None]
		generated_encrypted_file = bytearray()
		#WRITING SALT TO FILE, INIT CIPHERS
		for i in range(0,4):
			if self.files_ok[i] == True:
				if self.using_gui:
					self.qtobj.write_to_status_bar("Creating keyslot "+str(i))
				generated_keyslots[i] = generate_keyslot(self.password_list[i])
				generated_keyslots_keys_from_master[i] = generate_keys_from_master(generated_keyslots[i][1])
				generated_encrypted_file.extend(generated_keyslots[i][0])
				cipher_slots[i] = AES256_CTR(generated_keyslots_keys_from_master[i][0]) #using first key
			else:
				generated_encrypted_file.extend(Random.get_random_bytes(64))
		#WRITING FINAL SHARED HMAC KEY
		for i in range(0,4):
			if self.files_ok[i] == True:
				current_hmac_encrypted_key = do_xor_on_bytes(generated_final_hmac_key, generated_keyslots_keys_from_master[i][3])
				generated_encrypted_file.extend(current_hmac_encrypted_key)
			else:
				generated_encrypted_file.extend(Random.get_random_bytes(32))
		#WRITING LENGTHS
		for i in range(0,4):
			if self.files_ok[i] == True:
				encrypted_init_length = cipher_slots[i].encrypt(self.inner_lengths[i][0].to_bytes(8, byteorder='little'))
				encrypted_end_length = cipher_slots[i].encrypt(self.inner_lengths[i][1].to_bytes(8, byteorder='little'))
				generated_encrypted_file.extend(encrypted_init_length)
				generated_encrypted_file.extend(encrypted_end_length)
			else:
				generated_encrypted_file.extend(Random.get_random_bytes(16))
		#CALCULATING HMAC1
		for i in range(0,4):
			if self.files_ok[i] == True:
				#using second key
				calculated_hmac1[i] = calculate_hmac1_hmac2(generated_encrypted_file, generated_keyslots_keys_from_master[i][1])
		#writing HMAC1
		for i in range(0,4):
			if self.files_ok[i] == True:
				generated_encrypted_file.extend(calculated_hmac1[i])
			else:
				generated_encrypted_file.extend(Random.get_random_bytes(64))
		#writing P1, EF1, P2, EF2, P3, EF3, P4, EF4
		for i in range(0,4):
			generated_encrypted_file.extend(Random.get_random_bytes(self.padding_sizes[i]))
			if self.files_ok[i] == True:
				if self.using_gui:
					self.qtobj.write_to_status_bar("Encrypting File "+str(i))
				generated_encrypted_file.extend(cipher_slots[i].encrypt(self.files_read[i]))
			else:
				pass
		#WRITING P5
		generated_encrypted_file.extend(Random.get_random_bytes(self.padding_sizes[4]))
		#CALCULATING HMAC2
		for i in range(0,4):
			if self.files_ok[i] == True:
				#using third key
				calculated_hmac2[i] = calculate_hmac1_hmac2(generated_encrypted_file, generated_keyslots_keys_from_master[i][2])
		#writing HMAC2
		for i in range(0,4):
			if self.files_ok[i] == True:
				generated_encrypted_file.extend(calculated_hmac2[i])
			else:
				generated_encrypted_file.extend(Random.get_random_bytes(64))
		#calculating FINAL HMAC
		final_hmac = calculate_hmac1_hmac2(generated_encrypted_file, generated_final_hmac_key)
		#writing final HMAC
		generated_encrypted_file.extend(final_hmac)
		# ~ print("WRITTEN FINAL HMAC:", final_hmac)
		# ~ print("KEYS:",generated_keyslots)
		# ~ print("KEYS FROM MASTER")
		# ~ print(generated_keyslots_keys_from_master)
		# ~ print("FILE LENGTH:", len(generated_encrypted_file))
		return generated_encrypted_file

class MAIN_DECRYPT(object):
	def __init__(self, qtobj=None):
		self.qtobj = qtobj
		self.using_gui = True if self.qtobj != None else False
		self.steg_size = -1
		self.padding_init = False
		self.padding_sizes = [0,0,0,0,0]
		self.inner_lengths = [None, None]
		self.encryption_ready = False
		self.encrypted_data = None
		self.password_init = False
		# paddings are:
		# PADDING 1 FILE 1 P2 F2 P3 F3 P4 F4 P5
	def reset(self):
		pass
	def set_input_data(self, data):
		self.encrypted_data = data
		self.encrypted_data_length = len(self.encrypted_data)
		if self.encrypted_data_length < 1000:
			return False
	def set_output_file(self, file_location):
		self.output_file = file_location
		return True
	def set_password_and_slot(self, password, slot):
		self.password = password
		self.slot = slot
		self.password_and_slot_init = True
		return True
	def obtain_keys_from_master(self):
		self.current_salt = self.encrypted_data[64*self.slot:64*(self.slot+1)]
		# ~ self.current_keyslot_keys_from_master = None, None, None, None
		if self.using_gui:
			self.qtobj.write_to_status_bar("Reading Keyslot")
		self.current_keyslot_keys_from_master = generate_keys_from_master(read_keyslot(self.current_salt, self.password))
		self.cipher_slot = AES256_CTR(self.current_keyslot_keys_from_master[0])
	def verify_hmac1(self):
		#generating keys/randomness
		read_hmac1 = self.encrypted_data[448+64*(self.slot):448+64*(self.slot+1)]
		calculated_hmac1 = calculate_hmac1_hmac2(self.encrypted_data[:448],self.current_keyslot_keys_from_master[1])
		# ~ print("R HMAC1:",read_hmac1)
		# ~ print("C HMAC1:",calculated_hmac1)
		return hmac.compare_digest(read_hmac1, calculated_hmac1)
	def verify_final_hmac(self):
		final_hmac_key = do_xor_on_bytes(self.encrypted_data[256+32*(self.slot):256+32*(self.slot+1)], self.current_keyslot_keys_from_master[3])
		calculated_final_hmac = calculate_hmac1_hmac2(self.encrypted_data[:-64], final_hmac_key)
		read_final_hmac = self.encrypted_data[-64:]
		# ~ print("R HMACF:",read_final_hmac)
		# ~ print("C HMACF:",calculated_final_hmac)
		return hmac.compare_digest(read_final_hmac, calculated_final_hmac)
	def verify_hmac2(self):
		read_hmac2 = self.encrypted_data[-320+64*(self.slot):-320+64*(self.slot+1)]
		calculated_hmac2 = calculate_hmac1_hmac2(self.encrypted_data[:-320],self.current_keyslot_keys_from_master[2])
		# ~ print("R HMAC2:",read_hmac2)
		# ~ print("C HMAC2:",calculated_hmac2)
		return hmac.compare_digest(read_hmac2, calculated_hmac2)
	def process_length(self):
		length_pack = self.cipher_slot.encrypt(self.encrypted_data[384+16*(self.slot):384+16*(self.slot+1)])
		self.init_length = int.from_bytes(length_pack[:8], byteorder='little')
		self.end_length = int.from_bytes(length_pack[8:], byteorder='little')
		if self.using_gui:
			self.qtobj.write_to_status_bar("INIT LENGTH: "+str(self.init_length)+" END LENGTH: "+str(self.end_length))
		print("INIT LENGTH:",self.init_length, "END LENGTH:",self.end_length)
		if self.init_length >= self.encrypted_data_length or self.end_length >= self.encrypted_data_length:
			return False
		return True
	def decrypt_file(self):
		if self.using_gui:
			self.qtobj.write_to_status_bar("Decrypting File")
		decrypted_data = self.cipher_slot.encrypt(self.encrypted_data[self.init_length:self.end_length])
		if self.using_gui:
			self.qtobj.write_to_status_bar("Writing to Disk")
		write_file_from_bytearray(self.output_file, decrypted_data)
		infolist =	[["DECRYPTED FILE MD5:",		hashlib.md5(decrypted_data).hexdigest(),	"\n"],
					["DECRYPTED FILE SHA1:",		hashlib.sha1(decrypted_data).hexdigest(),	"\n"],
					["DECRYPTED FILE SHA256:",		hashlib.sha256(decrypted_data).hexdigest(),	"\n"]]
		infotemplist = [" ".join(infolistline) for infolistline in infolist]
		infostr = "".join(infotemplist)
		if self.using_gui:
			self.qtobj.show_information_message("Decrypted File Data", infostr)
		print(infostr)
		
#wave stuff

import wave

def read_wave_parameters(file_name):
	test_file = wave.open(file_name,'rb')
	parameters = test_file.getparams()
	test_file.close()
	return parameters

def calculate_max_wave_encryption(file_name):
	parameters = read_wave_parameters(file_name)
	return parameters[0]*parameters[1]*parameters[3] // 8

def read_wave_to_bytearray(file_name):
	test_file = wave.open(file_name,'rb')
	parameters = test_file.getparams()
	output = bytearray(test_file.readframes(parameters[3]))
	test_file.close()
	return output, parameters
	
def write_wave_from_bytearray(file_name,input_bytearray, parameters):
	if input_bytearray != None:
		test_file = wave.open(file_name,'wb')
		test_file.setparams(parameters)
		test_file.writeframesraw(input_bytearray)
		test_file.close()
	return True
	
def byte_to_2_bit_chunks(current_byte):
	chunk_list = []
	for i in range(0,4):
		chunk_list.append(current_byte & 0b11)
		current_byte >>= 2
	chunk_list.reverse()
	return chunk_list

def bit_2_chunks_to_byte(chunks):
	byte_output = 0
	for i in range(0,4):
		byte_output <<= 2
		byte_output |= chunks[i]
	#print(byte_output)
	return byte_output
	
def merge_bytearray_and_wav(input_bytearray, wav_bytearray):
	cf = 0
	out_bytearray = bytearray()
	len_in = len(input_bytearray)
	pc = max(len_in // 224,1)
	cnt = 0
	for i in range(0,len_in):
		current_byte = input_bytearray[i]
		current_chunks = byte_to_2_bit_chunks(current_byte)
		#print(current_chunks)
		# Here we are splitting a byte into four 2-bit chunks. As WAVs are little-endian,
		# and 16 bit per channel per sample, we must interleave the storage. The program
		# will store one byte in two 16-bit stereo frames (one byte per eight bytes).
		# This collects each byte in the original wav.
		b1, b2, b3, b4, b5, b6, b7, b8 = wav_bytearray[i*8], wav_bytearray[(i*8)+1], wav_bytearray[(i*8)+2], wav_bytearray[(i*8)+3], wav_bytearray[(i*8)+4], wav_bytearray[(i*8)+5], wav_bytearray[(i*8)+6], wav_bytearray[(i*8)+7]
		# This removes the last two bits and stores the needed info there.
		b1 &= 0b11111100
		b1 |= current_chunks[0]
		b3 &= 0b11111100
		b3 |= current_chunks[1]
		b5 &= 0b11111100
		b5 |= current_chunks[2]
		b7 &= 0b11111100
		b7 |= current_chunks[3]
		#print(b1&0b11,b3&0b11,b5&0b11,b7&0b11)
		#print(b1, b2, b3, b4, b5, b6, b7, b8)
		# This reassembles the WAV.
		out_bytearray.extend(bytes([b1,b2,b3,b4,b5,b6,b7,b8]))
	cpos = (len_in*8)
	pc = max((len(wav_bytearray)-cpos) // 224,1)
	# Most times, the file won't fit exactly into the WAV. So we must fill out that
	# space, to avoid creating a noticeable difference that possibly leaks the file
	# length, or makes the steganography more obvious.
	print("WAV PADDING REQUIRED:",len(wav_bytearray)-cpos)
	while cpos < len(wav_bytearray):
		if cpos % 2 == 0:
			out_bytearray.append((wav_bytearray[cpos]&0b11111100)|random.randint(0,3))
		else:
			out_bytearray.append(wav_bytearray[cpos])
		cpos +=1
	return out_bytearray
def get_bytearray_from_wav(wav_bytearray):
	out_bytearray = bytearray()
	ltu = len(wav_bytearray) // 8
	for i in range(0,ltu):
		#print(i)
		#print(len(wav_bytearray))
		b1, b2, b3, b4, b5, b6, b7, b8 = wav_bytearray[i*8], wav_bytearray[(i*8)+1], wav_bytearray[(i*8)+2], wav_bytearray[(i*8)+3], wav_bytearray[(i*8)+4], wav_bytearray[(i*8)+5], wav_bytearray[(i*8)+6], wav_bytearray[(i*8)+7]
		# This recovers everything from the WAV, including the padding garbage at the end.
		current_chunks = [b1&0b11,b3&0b11,b5&0b11,b7&0b11]
		current_byte = bit_2_chunks_to_byte(current_chunks)
		out_bytearray.append(current_byte)
	return out_bytearray

class main_window(QMainWindow):
	def __init__(self):
		super().__init__()
		# self.init_info()
		self.init_gui()
		# self.prueba_inicializacion()
	# def init_info(self):
	# 	self.archivo_db_abierto = None
	def show_error_message(self, title, message=None):
		if message==None: message=title
		QMessageBox.critical(self, title, message, QMessageBox.Ok)
	def show_dissuasive_message(self, title, message):
		override = QMessageBox.critical(self, title, message, QMessageBox.No | QMessageBox.Yes, QMessageBox.No)
		if override == QMessageBox.No:
			return False
		else:
			override = QMessageBox.critical(self, "CONFIRM DANGEROUS ACTION", "ARE YOU REALLY SURE? THIS IS ACTUALLY DANGEROUS", QMessageBox.No | QMessageBox.Yes, QMessageBox.No)
			if override == QMessageBox.No:
				return False
			else:
				return True
	def show_information_message(self, title, message=None):
		if message==None: message=title
		QMessageBox.information(self, title, message, QMessageBox.Ok)
	def write_to_status_bar(self, message):
		self.statusBar().showMessage(message)
		QApplication.processEvents()
	def init_gui(self):
		self.main_widget = QWidget()
		try:
			cur_dir = os.path.dirname(os.path.realpath(__file__))
			self.setWindowIcon(QIcon(cur_dir + os.path.sep + 'icon.png'))
		except:
			print("icon load failed")
		self.setCentralWidget(self.main_widget)
		self.init_main_widget()
		self.setWindowTitle(PROGRAM_NAME)
		self.statusBar().showMessage('Ready')
		self.setGeometry(300, 300, 600, 300)

		self.show()
	def init_main_widget(self):
		self.work_mode = 0
		self.main_widget_vbox_0 = QVBoxLayout()
		self.main_widget_grid_0 = QGridLayout()
		self.main_widget_hbox_0 = QHBoxLayout()
		self.main_widget_hbox_1 = QHBoxLayout()
		self.main_widget_hbox_2 = QHBoxLayout()
		self.main_widget_hbox_3 = QHBoxLayout()
		# self.main_widget_hbox_4 = QHBoxLayout()
		self.main_widget_radio_list = [QRadioButton("Encrypt NON-STEG"), QRadioButton("Encrypt STEG"), QRadioButton("Decrypt NON-STEG"), QRadioButton("Decrypt STEG")]
		self.main_widget_radio_list[0].setChecked(True)
		self.main_widget_radio_groupbox = QGroupBox()
		self.main_widget_radio_groupbox_hbox = QHBoxLayout()
		for i in range(0,4):
			self.main_widget_radio_groupbox_hbox.addWidget(self.main_widget_radio_list[i])
			self.main_widget_radio_list[i].clicked.connect(lambda state, i=i: self.set_work_mode(i))
		self.main_widget_radio_groupbox.setLayout(self.main_widget_radio_groupbox_hbox)
		self.main_widget_crypto_file_location = None
		self.main_widget_crypto_file_label = QLabel('Container File:')
		self.main_widget_crypto_file_label.setSizePolicy(SIZE_POLICY_FIXED_LABEL)
		self.main_widget_crypto_file_sel = QLabel('')
		self.main_widget_crypto_file_sel.setSizePolicy(SIZE_POLICY_FILE_NAMES)
		self.main_widget_crypto_file_btn = QPushButton("SET")
		self.main_widget_crypto_file_btn.clicked.connect(self.update_crypto_file)
		self.main_widget_grid_0.addWidget(self.main_widget_crypto_file_label, 0, 1)
		self.main_widget_grid_0.addWidget(self.main_widget_crypto_file_sel, 0, 2)
		self.main_widget_grid_0.addWidget(self.main_widget_crypto_file_btn, 0, 3)
		self.main_widget_crypto_wavdest_file_location = None
		self.main_widget_crypto_wavdest_file_label = QLabel('STEG Destination File:')
		self.main_widget_crypto_wavdest_file_label.setSizePolicy(SIZE_POLICY_FIXED_LABEL)
		self.main_widget_crypto_wavdest_file_sel = QLabel('')
		self.main_widget_crypto_wavdest_file_sel.setSizePolicy(SIZE_POLICY_FILE_NAMES)
		self.main_widget_crypto_wavdest_file_btn = QPushButton("SET")
		self.main_widget_crypto_wavdest_file_btn.clicked.connect(self.update_crypto_wavdest_file)
		self.main_widget_crypto_wavdest_file_btn.hide()
		self.main_widget_crypto_wavdest_file_label.hide()
		self.main_widget_crypto_wavdest_file_sel.hide()
		self.main_widget_grid_0.addWidget(self.main_widget_crypto_wavdest_file_label, 1, 1)
		self.main_widget_grid_0.addWidget(self.main_widget_crypto_wavdest_file_sel, 1, 2)
		self.main_widget_grid_0.addWidget(self.main_widget_crypto_wavdest_file_btn, 1, 3)
		# self.main_widget_hbox_0.addStretch(1)
		self.main_widget_source_file_location_list = []
		self.main_widget_source_file_label_list = []
		self.main_widget_source_file_title_label_list = []
		self.main_widget_source_file_checkbox_use_list = []
		self.main_widget_source_file_btn_list = []
		self.main_widget_source_file_size_label_list = []
		self.main_widget_source_file_size_title_label_list = []
		for i in range(0,4):
			self.main_widget_source_file_location_list.append([None, None, None])
			self.main_widget_source_file_label_list.append(QLabel(''))
			self.main_widget_source_file_label_list[-1].setSizePolicy(SIZE_POLICY_FILE_NAMES)
			self.main_widget_source_file_title_label_list.append(QLabel('Source File:'))
			self.main_widget_source_file_title_label_list[-1].setSizePolicy(SIZE_POLICY_FIXED_LABEL)
			self.main_widget_source_file_checkbox_use_list.append(QCheckBox())
			self.main_widget_source_file_checkbox_use_list[-1].setSizePolicy(SIZE_POLICY_FIXED_LABEL)
			self.main_widget_source_file_checkbox_use_list[-1].stateChanged.connect(lambda state, i=i: self.update_use_flag(i, state))
			self.main_widget_source_file_btn_list.append(QPushButton("SET"))
			self.main_widget_source_file_btn_list[-1].clicked.connect(lambda state, i=i: self.update_action_source_files(i))
			self.main_widget_source_file_btn_list[-1].setEnabled(False)
			self.main_widget_source_file_size_label_list.append(QLabel(''))
			self.main_widget_source_file_size_title_label_list.append(QLabel('Size:'))
			self.main_widget_grid_0.addWidget(self.main_widget_source_file_checkbox_use_list[-1], i+2, 0)
			self.main_widget_grid_0.addWidget(self.main_widget_source_file_title_label_list[-1], i+2, 1)
			self.main_widget_grid_0.addWidget(self.main_widget_source_file_label_list[-1], i+2, 2)
			self.main_widget_grid_0.addWidget(self.main_widget_source_file_btn_list[-1], i+2, 3)
			self.main_widget_grid_0.addWidget(self.main_widget_source_file_size_title_label_list[-1], i+2, 4)
			self.main_widget_grid_0.addWidget(self.main_widget_source_file_size_label_list[-1], i+2, 5)
		self.main_widget_required_steg_size = None
		self.main_widget_current_steg_size = None
		self.main_widget_steg_labels = [QLabel("Required Steg Size"), QLabel(''), QLabel("Current Steg Size"), QLabel('')]
		for i in range(0,4):
			self.main_widget_hbox_0.addWidget(self.main_widget_steg_labels[i])
			self.main_widget_steg_labels[i].hide()


		self.main_widget_btn_action = QPushButton("Encrypt")
		self.main_widget_btn_action.setEnabled(False)
		self.main_widget_btn_action.clicked.connect(self.execute_main_action)
		self.main_widget_btn_clear = QPushButton("Clear")
		self.main_widget_btn_clear.clicked.connect(self.btn_clear_action)
		self.main_widget_hbox_1.addWidget(self.main_widget_btn_action)
		self.main_widget_hbox_1.addWidget(self.main_widget_btn_clear)

		self.main_widget_hbox_1.addStretch(1)
		# self.main_widget_hbox_4.addStretch(1)
		# self.main_widget_hbox_0 = QHBoxLayout()
		# self.main_widget_hbox_0.addStretch(1)
		self.main_widget_vbox_0.addWidget(self.main_widget_radio_groupbox)
		self.main_widget_vbox_0.addLayout(self.main_widget_grid_0)
		self.main_widget_vbox_0.addStretch()
		self.main_widget_vbox_0.addLayout(self.main_widget_hbox_0)
		self.main_widget_vbox_0.addLayout(self.main_widget_hbox_1)

		# self.main_widget_vbox_0.addLayout(self.main_widget_hbox_4)
		self.main_widget_vbox_0.addStretch(1)
		self.main_widget.setLayout(self.main_widget_vbox_0)
		self.main_widget.show()
	def set_work_mode(self, i):
		#this function works both as a general gui reset, and to actually set the work mode.
		self.work_mode = i
		for j in range(0,4):
			self.main_widget_source_file_location_list[j] = [None, None, None]
			self.main_widget_source_file_label_list[j].setText('')
			self.main_widget_source_file_size_label_list[j].setText('')
			self.main_widget_current_steg_size = None
			self.main_widget_required_steg_size = None
			self.main_widget_steg_labels[1].setText(str(TOTAL_OVERHEAD_LENGTH))
			self.main_widget_steg_labels[3].setText('')
			self.main_widget_source_file_title_label_list[j]
			self.main_widget_source_file_checkbox_use_list[j].setEnabled(True)
			self.main_widget_source_file_checkbox_use_list[j].setChecked(False)
			self.main_widget_source_file_btn_list[j].setEnabled(False)
			self.main_widget_crypto_file_location = None
			self.main_widget_crypto_file_sel.setText('')
			self.main_widget_crypto_wavdest_file_location = None
			self.main_widget_crypto_wavdest_file_sel.setText('')
			if i in [0,1]:
				self.main_widget_btn_action.setText("Encrypt")
				self.main_widget_source_file_title_label_list[j].setText('Source File:')
				self.main_widget_source_file_size_title_label_list[j].show()
				self.main_widget_source_file_size_label_list[j].show()
			elif i in [2,3]:
				self.main_widget_btn_action.setText("Decrypt")
				self.main_widget_source_file_title_label_list[j].setText('Destination File:')
				self.main_widget_source_file_size_title_label_list[j].hide()
				self.main_widget_source_file_size_label_list[j].hide()
			if i in [0,2,3]:
				# self.main_widget_source_file_size_label_list[j].hide()
				self.main_widget_steg_labels[j].hide()
				self.main_widget_crypto_wavdest_file_btn.hide()
				self.main_widget_crypto_wavdest_file_label.hide()
				self.main_widget_crypto_wavdest_file_sel.hide()
			elif i == 1:
				# self.main_widget_source_file_size_label_list[j].show()
				self.main_widget_steg_labels[j].show()
				self.main_widget_crypto_wavdest_file_btn.show()
				self.main_widget_crypto_wavdest_file_label.show()
				self.main_widget_crypto_wavdest_file_sel.show()
	def update_crypto_file(self):
		if self.work_mode == 0:
			file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", "")
			if file_name:
				pass
			else:
				return
		elif self.work_mode == 1:
			file_name, _ = QFileDialog.getOpenFileName(self, "Open WAV Source File", "", "WAV Audio (*.wav);;All Files (*.*)")
			if file_name:
				if is_file_accessible(file_name):
					try:
						max_length = calculate_max_wave_encryption(file_name)
						self.main_widget_current_steg_size = max_length
						self.main_widget_steg_labels[3].setText(str(max_length))
					except:
						self.show_error_message("INVALID WAV FILE", "INVALID WAV FILE")
						return
					if max_length <= TOTAL_OVERHEAD_LENGTH:
						self.show_error_message("WAV TOO SHORT", "WAV TOO SHORT")
						return
				else:
					return
			else:
				return
		elif self.work_mode == 2:
			file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "")
			if file_name:
				if is_file_accessible(file_name):
					pass
				else:
					return
			else:
				return
		elif self.work_mode == 3:
			file_name, _ = QFileDialog.getOpenFileName(self, "Open WAV Source File", "", "WAV Audio (*.wav);;All Files (*.*)")
			if file_name:
				if is_file_accessible(file_name):
					try:
						max_length = calculate_max_wave_encryption(file_name)
					except:
						self.show_error_message("INVALID WAV FILE", "INVALID WAV FILE")
						return
					if max_length <= TOTAL_OVERHEAD_LENGTH:
						self.show_error_message("WAV TOO SHORT", "WAV TOO SHORT")
						return
				else:
					return
			else:
				return
		self.main_widget_crypto_file_location = file_name
		self.main_widget_crypto_file_sel.setText(file_name)
	def update_crypto_wavdest_file(self):
		file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "",  "WAV Audio (*.wav);;All Files (*.*)")
		if file_name:
			pass
		else:
			return
		self.main_widget_crypto_wavdest_file_location = file_name
		self.main_widget_crypto_wavdest_file_sel.setText(file_name)
	def update_use_flag(self, i, state):
		self.main_widget_source_file_btn_list[i].setEnabled(state)
		#this is to only allow one decryption slot at a time.
		if self.work_mode in [2,3]:
			for j in range(0,4):
				if j != i:
					self.main_widget_source_file_checkbox_use_list[j].setEnabled(not state)
		self.update_action_button()
	def update_action_source_files(self, i):
		if self.work_mode in [0,1]:
			file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "")
			if file_name:
				if is_file_accessible(file_name):
					file_length = read_file_length(file_name)
				else:
					self.show_error_message("FILE NOT ACCESSIBLE")
					return
			else:
				return
			obj_pw = object_encrypt_password_helper_dialog(self)
			if obj_pw.dialog.exec_() == QDialog.Accepted:
				password = obj_pw.password
				self.main_widget_source_file_location_list[i] = [file_name, password, file_length]
				self.main_widget_source_file_label_list[i].setText(file_name)
				self.main_widget_source_file_size_label_list[i].setText(str(file_length))
				if self.work_mode == 1:
					self.update_required_length()
		elif self.work_mode in [2,3]:
			file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", "")
			if file_name:
				pass
			else:
				return
			obj_pw = object_decrypt_password_helper_dialog(self)
			if obj_pw.dialog.exec_() == QDialog.Accepted:
				password = obj_pw.password
				self.main_widget_source_file_location_list[i] = [file_name, password, None]
				self.main_widget_source_file_label_list[i].setText(file_name)
		self.update_action_button()
	def update_action_button(self):
		self.update_required_length()
		is_enabled = False
		disable_flag = False
		for i in range(0,4):
			if self.main_widget_source_file_checkbox_use_list[i].isChecked():
				if self.main_widget_source_file_location_list[i] != [None, None, None]:
					is_enabled = True
				else:
					disable_flag = True
		if self.main_widget_crypto_file_location == None:
			disable_flag = True
		if self.work_mode == 1:
			if self.main_widget_crypto_wavdest_file_location == None:
				disable_flag = True
			elif self.main_widget_required_steg_size == None or  self.main_widget_current_steg_size == None:
				disable_flag = True
			elif self.main_widget_required_steg_size > self.main_widget_current_steg_size:
				disable_flag = True
		self.main_widget_btn_action.setEnabled(is_enabled & ~ disable_flag)
	def update_required_length(self):
		length = 0
		for i in range(0,4):
			if self.main_widget_source_file_checkbox_use_list[i].isChecked() == True and self.main_widget_source_file_location_list[i][2] != None:
				length += self.main_widget_source_file_location_list[i][2]
		self.main_widget_required_steg_size = length+TOTAL_OVERHEAD_LENGTH
		self.main_widget_steg_labels[1].setText(str(self.main_widget_required_steg_size))
	def btn_clear_action(self):
		self.set_work_mode(self.work_mode)
	def find_current_decryption_slot(self):
		for i in range(0,4):
			if self.main_widget_source_file_checkbox_use_list[i].isChecked():
				return self.main_widget_source_file_location_list[i][0], self.main_widget_source_file_location_list[i][1], i
		self.show_error_message("Slot Error", "Please report this bug")
	def execute_main_action(self):
		file_location_list = [file_info[0] for file_info in self.main_widget_source_file_location_list]
		file_password_list = [file_info[1] for file_info in self.main_widget_source_file_location_list]
		if self.work_mode in [0,1]:
			encrypt_object = MAIN_ENCRYPT(self)
			if self.work_mode == 1:
				encrypt_object.init_steg(self.main_widget_current_steg_size)
			encrypt_object.set_input_files(file_location_list)
			encrypt_object.calculate_paddings_and_lengths()
			encrypt_object.input_passwords(file_password_list)
			encrypted_final_data = encrypt_object.generate_encrypted_data()
			if self.work_mode == 1:
				self.write_to_status_bar("Reading WAV")
				wav_data, wav_params = read_wave_to_bytearray(self.main_widget_crypto_file_location)
				self.write_to_status_bar("Merging WAV")
				merged_data = merge_bytearray_and_wav(encrypted_final_data, wav_data)
				self.write_to_status_bar("Writing WAV")
				write_wave_from_bytearray(self.main_widget_crypto_wavdest_file_location, merged_data, wav_params)
			else:
				self.write_to_status_bar("Writing File")
				write_file_from_bytearray(self.main_widget_crypto_file_location, encrypted_final_data)
		elif self.work_mode in [2,3]:
			decrypt_obj = MAIN_DECRYPT(self)
			if self.work_mode == 2:
				if read_file_length(self.main_widget_crypto_file_location) <= TOTAL_OVERHEAD_LENGTH:
					self.show_error_message("FILE TOO SMALL", "FILE TOO SMALL")
					return
				self.write_to_status_bar("Reading Crypto File")
				encrypted_initial_data = read_file_to_bytearray(self.main_widget_crypto_file_location)
			if self.work_mode == 3:
				try:
					self.write_to_status_bar("Testing WAV")
					max_wav = calculate_max_wave_encryption(self.main_widget_crypto_file_location)
					self.write_to_status_bar("Reading WAV")
					wav_data, wav_params = read_wave_to_bytearray(self.main_widget_crypto_file_location)
					self.write_to_status_bar("Getting Data from WAV")
					encrypted_initial_data = get_bytearray_from_wav(wav_data)
				except:
					self.show_error_message("INVALID WAV FILE", "INVALID WAV FILE")
					return
				if max_wav <= TOTAL_OVERHEAD_LENGTH:
					self.show_error_message("WAV TOO SHORT", "WAV TOO SHORT")
					return
			current_output_file, current_password, current_slot = self.find_current_decryption_slot()
			decrypt_obj.set_input_data(encrypted_initial_data)
			decrypt_obj.set_output_file(current_output_file)
			decrypt_obj.set_password_and_slot(current_password, current_slot)
			decrypt_obj.obtain_keys_from_master()
			hmac1_ok = decrypt_obj.verify_hmac1()
			if hmac1_ok == True:
				self.show_information_message("HMAC1 OK", "HMAC1 OK, KEY MATERIAL VERIFIED")
			else:
				cont = self.show_dissuasive_message("HMAC1 NOT OK", HMAC1_DISSUASIVE_TEXT)
				if cont == False:
					return False
			hmac_final_ok = decrypt_obj.verify_final_hmac()
			if hmac_final_ok == True:
				self.show_information_message("FINAL HMAC OK", "FINAL HMAC OK, SHARED-KEY FILE INTEG. VERIFIED")
			else:
				cont = self.show_dissuasive_message("FINAL HMAC NOT OK", FINAL_HMAC_DISSUASIVE_TEXT)
				if cont == False:
					return False
			hmac2_ok = decrypt_obj.verify_hmac2()
			if hmac2_ok == True:
				self.show_information_message("HMAC2 OK","HMAC2 OK, FILE INTEGRITY VERIFIED")
			else:
				cont = self.show_dissuasive_message("HMAC2 NOT OK", HMAC2_DISSUASIVE_TEXT)
				if cont == False:
					return False
			len_ok = decrypt_obj.process_length()
			if len_ok == True:
				self.show_information_message("LENGTH OK", "LENGTH OK")
			else:
				self.show_error_message("LENGTH NOT OK", "MALFORMED FILE, CAN'T DECRYPT")
				return False
			decrypt_obj.decrypt_file()
		self.write_to_status_bar("Ready")

	def closeEvent(self, event):
		qApp.exit()
	
class object_encrypt_password_helper_dialog(object):
	def __init__(self, main_dialog):
		self.main_dialog = main_dialog
		self.dialog = QDialog()
		self.grid = QGridLayout()
		self.pwlabel_1 = QLabel("PW:")
		self.pwlabel_2 = QLabel("PW:")
		self.pw_lineedit_1 = QLineEdit()
		self.pw_lineedit_1.setEchoMode(QLineEdit.Password)
		self.pw_lineedit_2 = QLineEdit()
		self.pw_lineedit_2.setEchoMode(QLineEdit.Password)
		self.pw_lineedit_1.textChanged.connect(self.pw_changed)
		self.pw_lineedit_2.textChanged.connect(self.pw_changed)
		self.btn_ok = QPushButton("OK")
		self.btn_ok.setEnabled(False)
		self.btn_ok.clicked.connect(self.return_pw)
		self.btn_cancel = QPushButton("Cancel")
		self.btn_cancel.clicked.connect(self.return_cancel)
		self.grid.addWidget(self.pwlabel_1, 0, 0)
		self.grid.addWidget(self.pwlabel_2, 1, 0)
		self.grid.addWidget(self.pw_lineedit_1, 0, 1)
		self.grid.addWidget(self.pw_lineedit_2, 1, 1)
		self.grid.addWidget(self.btn_ok, 2, 1)
		self.grid.addWidget(self.btn_cancel, 2, 0)
		self.dialog.setWindowTitle("Get Encrypt Password")
		self.dialog.setModal(True)
		self.dialog.setLayout(self.grid)
	def pw_changed(self, pw_text):
		self.btn_ok.setEnabled(self.pw_lineedit_1.text() == self.pw_lineedit_2.text() and len(self.pw_lineedit_1.text()) >= MINIMUM_PASSWORD_SIZE_ENCRYPTION)
	def return_pw(self):
		self.password = self.pw_lineedit_1.text()
		self.dialog.accept()
	def return_cancel(self):
		self.dialog.reject()

class object_decrypt_password_helper_dialog(object):
	def __init__(self, main_dialog):
		self.main_dialog = main_dialog
		self.dialog = QDialog()
		self.grid = QGridLayout()
		self.pwlabel_1 = QLabel("PW:")
		self.pw_lineedit_1 = QLineEdit()
		self.pw_lineedit_1.setEchoMode(QLineEdit.Password)
		self.btn_ok = QPushButton("OK")
		self.btn_ok.clicked.connect(self.return_pw)
		self.btn_cancel = QPushButton("Cancel")
		self.btn_cancel.clicked.connect(self.return_cancel)
		self.grid.addWidget(self.pwlabel_1, 0, 0)
		self.grid.addWidget(self.pw_lineedit_1, 0, 1)
		self.grid.addWidget(self.btn_ok, 1, 1)
		self.grid.addWidget(self.btn_cancel, 1, 0)
		self.dialog.setWindowTitle("Get Decrypt Password")
		self.dialog.setModal(True)
		self.dialog.setLayout(self.grid)
	def return_pw(self):
		self.password = self.pw_lineedit_1.text()
		self.dialog.accept()
	def return_cancel(self):
		self.dialog.reject()

if __name__ == '__main__':
	
	app = QApplication(sys.argv)
	V_MAIN = main_window()
	sys.exit(app.exec_())
