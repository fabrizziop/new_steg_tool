from Cryptodome import Random
from Cryptodome.Random import random
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import hashlib
import hmac
import time
import getpass

PROGRAM_NAME = "NewStegTool v2.0.0"


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
	def __init__(self):
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
		self.files_ok = [False, False, False, False]
		self.files_read = [False, False, False, False]
		self.files_length = [0,0,0,0]
		self.total_file_size = 0
		for i in range(0,4):
			if file_location_list[i] != False and is_file_accessible(file_location_list[i]) == True:
				try:
					self.files_read[i] = read_file_to_bytearray(file_location_list[i])
					self.files_length[i] = len(self.files_read[i])
					self.total_file_size += self.files_length[i]
					self.files_ok[i] = True
				except:
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
	def __init__(self):
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
		print("INIT LENGTH:",self.init_length, "END LENGTH:",self.end_length)
		if self.init_length >= self.encrypted_data_length or self.end_length >= self.encrypted_data_length:
			return False
		return True
	def decrypt_file(self):
		decrypted_data = self.cipher_slot.encrypt(self.encrypted_data[self.init_length:self.end_length])
		write_file_from_bytearray(self.output_file, decrypted_data)
		print("DECRYPTED FILE MD5:",hashlib.md5(decrypted_data).hexdigest())
		print("DECRYPTED FILE SHA1:",hashlib.sha1(decrypted_data).hexdigest())
		print("DECRYPTED FILE SHA256:",hashlib.sha256(decrypted_data).hexdigest())

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

class main_program_loop(object):
	def __init__(self):
		self.steg = False
		pass
		print("Welcome to", PROGRAM_NAME, "\n\n")
		self.main_menu()
	def print_memory(self):
		print("Steganography:", self.steg)
		print()
	def main_menu(self):
		while True:
			self.print_memory()
			print("--MAIN MENU--")
			print("Encrypt: 1, Decrypt: 2, Toggle STEG: 3, Quit: 0")
			t1 = self.handle_number_input([1,2,3,0])
			if t1 == 0:
				self.exit_program()
			elif t1 == 1:
				self.encrypt()
			elif t1 == 2:
				self.decrypt()
			elif t1 == 3:
				self.toggle_steg()
	def handle_number_input(self, allowed_values, default_print=""):
		fin_num = 0
		while True:
			tv = input(default_print)
			try:
				fin_num = int(tv)
				if fin_num in allowed_values:
					return fin_num
				else:
					print("Option does not exist!")
			except ValueError:
				print("Not a number, try again!")
	def handle_file_input(self, default_print="", must_exist=True):
		fin_fil = 0
		while True:
			tv = input(default_print)
			if must_exist:
				try:
					f = open(tv, 'rb')
					f.close()
					return tv
				except FileNotFoundError:
					print("File not found, try again!")
			else:
				return(tv)
	def get_length_of_steganography(self):
		length = 0
		for file_name in self.input_file_list:
			if file_name != None:
				length += read_file_length(file_name)
		return length+TOTAL_OVERHEAD_LENGTH
	def get_password(self, verify=True):
		if verify:
			while True:
				a = getpass.getpass("        Password: ")
				b = getpass.getpass("Confirm Password: ")
				if a == b:
					#add password strength meter!
					return a
				else:
					print("** PASSWORDS DO NOT MATCH **")
		else:
			return getpass.getpass("        Password: ")
	def toggle_steg(self):
		self.steg = not self.steg
	def exit_program(self):
		print("Bye.")
		quit()
	def encrypt(self):
		self.print_memory()
		encrypt_object = MAIN_ENCRYPT()
		slot_list = [1,2,3,4]
		self.password_list = [None, None, None, None]
		self.input_file_list = [None, None, None, None]
		print("How many files to encrypt? [1-4]:")
		amount_to_encrypt = self.handle_number_input(slot_list)
		for i in range(0, amount_to_encrypt):
			#asking for slot
			print("Select a slot")
			print("Available slot numbers:",slot_list)
			selected_slot = self.handle_number_input(slot_list)
			slot_list.pop(slot_list.index(selected_slot))
			print("File (INPUT) to encrypt inside slot",selected_slot,":")
			current_input_file = self.handle_file_input()
			#asking for password
			current_password = self.get_password()
			#asking for input file for the slot
			self.password_list[selected_slot-1] = current_password
			self.input_file_list[selected_slot-1] = current_input_file
		if self.steg == True:
			print("WAV File to hide data within:")
			input_wav_file = self.handle_file_input()
			try:
				max_wav = calculate_max_wave_encryption(input_wav_file)
			except:
				print("**Invalid WAV File**")
				max_wav = 0
			calculated_wav_len = self.get_length_of_steganography()
			print("Required capacity:", calculated_wav_len)
			print("Available capacity:", max_wav)
			if calculated_wav_len > max_wav:
				print("Files WILL NOT fit inside WAV. Try again!")
				return False
			encrypt_object.init_steg(max_wav)
			print("OUTPUT *WAV* File for encrypted data:")
			current_output_file = self.handle_file_input(must_exist = False)
		else:
			print("OUTPUT File for encrypted data:")
			current_output_file = self.handle_file_input(must_exist = False)
		encrypt_object.set_input_files(self.input_file_list)
		encrypt_object.calculate_paddings_and_lengths()
		encrypt_object.input_passwords(self.password_list)
		encrypted_final_data = encrypt_object.generate_encrypted_data()
		if self.steg == True:
			print("*READING AUDIO*")
			wav_data, wav_params = read_wave_to_bytearray(input_wav_file)
			print("*MERGING DATA AND AUDIO*")
			merged_data = merge_bytearray_and_wav(encrypted_final_data, wav_data)
			print("*WRITING NEW WAV*")
			write_wave_from_bytearray(current_output_file, merged_data, wav_params)
		else:
			write_file_from_bytearray(current_output_file, encrypted_final_data)
	def decrypt(self):
		self.print_memory()
		decrypt_obj = MAIN_DECRYPT()
		slot_list = [1,2,3,4]
		password = None
		input_file = None
		#asking for slot
		print("Select a slot")
		print("Available slot numbers:",slot_list)
		selected_slot = self.handle_number_input(slot_list)
		#asking for password
		current_password = self.get_password(verify=False)
		#asking for input file for the slot
		if self.steg == True:
			print("INPUT *WAV* File with encrypted data:")
			input_wav_file = self.handle_file_input()
			try:
				max_wav = calculate_max_wave_encryption(input_wav_file)
				wav_data, wav_params = read_wave_to_bytearray(input_wav_file)
				encrypted_initial_data = get_bytearray_from_wav(wav_data)
			except:
				print("*INVALID WAV FILE*")
				return False
			if max_wav <= TOTAL_OVERHEAD_LENGTH:
				print("*WAV TOO SHORT*")
				return False
		else:
			print("INPUT File with encrypted data:")
			current_input_file = self.handle_file_input()
			if read_file_length(current_input_file) <= TOTAL_OVERHEAD_LENGTH:
				print("*FILE TOO SMALL*")
				return False
			encrypted_initial_data = read_file_to_bytearray(current_input_file)
		print("OUTPUT File for encrypted data:")
		current_output_file = self.handle_file_input(must_exist = False)
		
		decrypt_obj.set_input_data(encrypted_initial_data)
		decrypt_obj.set_output_file(current_output_file)
		decrypt_obj.set_password_and_slot(current_password, selected_slot-1)
		decrypt_obj.obtain_keys_from_master()
		hmac1_ok = decrypt_obj.verify_hmac1()
		if hmac1_ok == True:
			print("HMAC1 OK, KEY MATERIAL VERIFIED")
		else:
			print("*****HMAC1 NOT OK, WRONG PASSWORD/DAMAGED FILE*****")
			print("You could try to decrypt this anyways, at your own risk")
			print("Do you want to continue (NOT RECOMMENDED)?")
			print("[1-5] No, [8] Yes")
			cont = self.handle_number_input([1,2,3,4,5,8])
			if cont != 8:
				return False
		hmac_final_ok = decrypt_obj.verify_final_hmac()
		if hmac_final_ok == True:
			print("FINAL HMAC OK, SHARED-KEY FILE INTEG. VERIFIED")
		else:
			print("*****FINAL HMAC NOT OK*****")
			print("*****POSSIBLE KEYSLOT GUESSING ATTACK*****")
			print("IF YOU CONTINUE AND HMAC2 IS OK, ANOTHER KEYSLOT")
			print("WAS POSSIBLY DAMAGED ON PURPOSE BY AN ATTACKER")
			print("TO FIND OUT IF YOU WERE USING THAT SLOT")
			print("Do you want to continue (NOT RECOMMENDED)?")
			print("[1-5] No, [8] Yes")
			cont = self.handle_number_input([1,2,3,4,5,8])
			if cont != 8:
				return False
		hmac2_ok = decrypt_obj.verify_hmac2()
		if hmac2_ok == True:
			print("HMAC2 OK, FILE INTEGRITY VERIFIED")
		else:
			print("*****HMAC2 NOT OK*****")
			print("*****FILE INTEGRITY NOT GUARANTEED*****")
			print("*****CONTINUE AT YOUR OWN RISK*****")
			print("Do you want to continue (NOT RECOMMENDED)?")
			print("[1-5] No, [8] Yes")
			cont = self.handle_number_input([1,2,3,4,5,8])
			if cont != 8:
				return False
		len_ok = decrypt_obj.process_length()
		if len_ok == True:
			print("LENGTH OK")
		else:
			print("MALFORMED FILE, CAN'T DECRYPT")
			return False
		decrypt_obj.decrypt_file()

main_program_loop()
