# -*- coding: utf-8 -*-
# author = smdll
from tkinter import *
from tkinter import messagebox, filedialog
import tempfile, zlib, base64, os

#图标数据
ICONDATA = "eNrtlUtMG1cUhn97xmaCzTCOGYbxAwgQe8z7YQzGpU7G+NGxjR2wcWihTVIrEi1FJBJN3aIqRamaVLCoUKqoUlhUSFSkYkWlLiJRukbqojuWXbAo6qYSElKl0pnxk7Rdt4t8M3Pvufefc+89Z3Q0gEa+mpshtxS+oYB6AIL8yFO4gvy8CokymsIjYzKZQNM0ahkGY6KIEY8HDRyHVDyGtrY25BYW8MWDB7DwPMb8fmw9eYKO9nbcyGTg8/kwm05h+c4dfLW6is3Hj/Hlo0f4YWcHz589w+LtLOZuvInvt7awu7mJ7MwbcDgG0OuZwYi4hP7hm8gkE/j26VM4nT3ocU/D4bqKmbkf8f5nf+Dewz+RvfszXN0xXBb8eP32cySmv8atxZ+Qefs75D4/w8LHv2I0+AFCiVU8/OhDCB0i7q78jgZLC97N/YKu/kncm38Hi/d/Q+qtHbQ6fBgancPaJ/dxc+EA72Vv4dNcDuvr61hZWUE8FsPS0hKy2SzcAwNYXVvD/Pw8Tk9Psb+/j8PDQywvL2NjYwPHx8fY3t7G7Ows0uk0Tk5OsLe3h93dXRwcHODo6Ah93d04OzvDS17yv0OjQlS0lai69u8QhHwXdXq6TISOqEO5oQu6wW/9R/wGIq+zXI1bFN3iuKh2omyIIsuxhoI/O8VTpM7AGCmaZAw6MkIZyYjOUtAJ2d8UTk4xmevhUDLDTCUDwfj1hM7K6omizkupNBNPhcdTcSYdTQSTqWuKf0mvZUITlDSuI0MSNREK0qHQpOxf2p+biEiTFC9FvBJPTUpBWpKCJV32rzdJ0RgTj/Lj0TgTU9aPXlP0Ynz1PBm4QI8FjMHAGB0KhCOvBcKqTqi6mRNJo5E0kjJyZ1QMI18RP2fJU+zzg+L+epbjuHr5eoGK+DkLe9XEV1uVaYu5QTYtsl4+n9XW2tjUaL/UwnFW3t7W1Gyvaqnc39ZxxSkIrvZLFo7v6FRMb1VF/utaO3uFYY/QbWdr6J5eoa9PcNmry/l1D3qEV0Zf9Ti9I/5Bn+Bo9w4LjQ3mwv56s6I3DdmHBe9I9aCvt2toyKHo+sL+5jq6U3A1dRXX7+sfcLrsbMX3t112lM+XN0vnU85vtdkb5aDU+Gyt5+NT88OxhaTIlPNT+r4FVFnJtDoqrq+/aM5TZz5nXCzoGsO/UKwfgq6lShVH5IuQMenz9aW8cKFaXaqiZrXGGp02PyfrpE6r05wraq2+iirrWuKcu/Ljl4ta88Lkf8JfHMDVgw=="

class acquireKey():
	def __init__(self, master):
		self.top = Toplevel(master)
		self.top.resizable(width = False, height = False) 
		Label(self.top, text = u"请输入密码：").pack(side = LEFT)
		self.keyInput = Entry(self.top, show = '*')
		self.keyInput.pack(side = LEFT, expand = True)
		self.keyInput.focus_set()
		Button(self.top, text = u"确认", command = self.cleanUp).pack(side = LEFT)
		self.top.wait_window(self.top)

	def cleanUp(self):
		self.key = self.keyInput.get()
		self.top.destroy()

class GUI:
	root = Tk()
	selectedAlgorihm = StringVar(root)
	def __init__(self):
		self.root.protocol("WM_DELETE_WINDOW", self.onExit)

		_, ICON_PATH = tempfile.mkstemp() #设置图标
		with open(ICON_PATH, 'wb') as icon_file:
			icon_file.write(zlib.decompress(base64.b64decode(ICONDATA)))
		self.root.iconbitmap(default = ICON_PATH)

		self.root.resizable(width = False, height = False) #禁止改变窗口尺寸
		self.root.title(u"gmssl-python")

		self.inputFilePane = PanedWindow(self.root)
		self.inputFilePane.pack(expand = True, fill = BOTH)
		Label(self.inputFilePane, text = u"输入文件：").pack(side = LEFT)
		self.inputFile = Entry(self.inputFilePane) #输入文件窗
		self.inputFile.pack(side = LEFT, expand = True, fill = BOTH)
		Button(self.inputFilePane, text = u"打开", command = lambda: self.onOpen(1)).pack(side = LEFT)

		self.outputFilePane = PanedWindow(self.root)
		self.outputFilePane.pack(expand = True, fill = BOTH)
		Label(self.outputFilePane, text = u"输出文件：").pack(side = LEFT)
		self.outputFile = Entry(self.outputFilePane) #输出文件窗
		self.outputFile.pack(side = LEFT, expand = True, fill = BOTH)
		Button(self.outputFilePane, text = u"打开", command = lambda: self.onOpen(2)).pack(side = LEFT)

		self.optionPane = PanedWindow(self.root)
		self.optionPane.pack(expand = True, fill = BOTH)
		Label(self.optionPane, text = u"算法:").pack(side = LEFT)
		self.selectedAlgorihm.set("SM2")
		OptionMenu(self.optionPane, self.selectedAlgorihm, "SM2", "SM4").pack(side = LEFT, expand = True, fill = BOTH) #算法选择

		Button(self.optionPane, text = u"加密", command = self.onEncrypt).pack(side = LEFT)
		Button(self.optionPane, text = u"解密", command = self.onDecrypt).pack(side = LEFT)
		Button(self.optionPane, text = u"签名(SM2)", command = self.onSign).pack(side = LEFT)
		Button(self.optionPane, text = u"验证(SM2)", command = self.onVerify).pack(side = LEFT)
		Button(self.optionPane, text = u"创建密钥对(SM2)", command = self.onGenerateKeyPair).pack(side = LEFT)
		Button(self.optionPane, text = u"计算哈希(SM3)", command = self.onGenerateHash).pack(side = LEFT)
		self.root.mainloop()

	def onOpen(self, choise):
		if choise == 1:
			File = filedialog.askopenfilename(initialdir = ".", title = u"选择文件")
			self.inputFile.delete(0, "end")
			self.inputFile.insert(0, File)
		else:
			File = filedialog.asksaveasfilename(initialdir = ".", title = u"选择文件")
			self.outputFile.delete(0, "end")
			self.outputFile.insert(0, File)

	def onEncrypt(self):
		if not (self.checkFile(self.inputFile.get(), 'r') or self.checkFile(self.outputFile.get(), 'w')):
			return
		if self.selectedAlgorihm.get() == "SM2":
			self.sm2Encrypt()
		else:
			self.sm4Encrypt()

	def onDecrypt(self):
		if not (self.checkFile(self.inputFile.get(), 'r') or self.checkFile(self.outputFile.get(), 'w')):
			return
		if self.selectedAlgorihm.get() == "SM2":
			self.sm2Decrypt()
		else:
			self.sm4Decrypt()

	def onSign(self):
		if not self.checkFile(self.inputFile.get(), 'r'):
			return
		self.sm2Sign()

	def onVerify(self):
		if not self.checkFile(self.inputFile.get(), 'r'):
			return
		self.sm2Verify()

	def onGenerateKeyPair(self):
		keyPairPath = filedialog.askdirectory(title = u"选择密钥对路径")
		if keyPairPath == '':
			return
		from gmssl.utils import PrivateKey
		priKey = PrivateKey()
		pubKey = priKey.publicKey()
		with open("%s\\key.pri"%keyPairPath, "wt") as f:
			f.write(priKey.toString())
		with open("%s\\key.pub"%keyPairPath, "wt") as f:
			f.write(pubKey.toString(compressed = False))
		messagebox.showinfo(u"生成结束", u"已写入%s\\key.pri\n%s\\key.pub"%(keyPairPath, keyPairPath))

	def onGenerateHash(self):
		if not self.checkFile(self.inputFile.get(), 'r'):
			return
		with open(self.inputFile.get(), "rb") as f:
			hash = self.sm3Hash(inputRaw = f.read())
		messagebox.showinfo(u"哈希结果", "%s"%hash)

	def onExit(self):
		self.root.destroy()

	def checkFile(self, filepath, mode):
		if mode == 'r':
			if not os.access(filepath, os.R_OK):
				messagebox.showerror(u"错误", u"输入文件无法打开！")
				return False
		else:
			if not os.access(filepath, os.W_OK):
				messagebox.showerror(u"错误", u"输出文件无效！")
				return False
		return True

	def sm2Sign(self):
		from gmssl.sm2 import CryptSM2
		from gmssl import func
		priKeyFile = filedialog.askopenfilename(initialdir = ".", title = u"选择私钥", filetypes = [("Private key", ("*.pri")), ("All files", "*.*")])
		if priKeyFile == '':
			return
		with open(priKeyFile, 'rt') as f:
			priKey = f.read()
		if len(priKey) < 32:
			messagebox.showerror(u"错误", u"私钥不正确！")
			del(priKey)
			return

		crypt_sm2 = CryptSM2(public_key = None, private_key = priKey)
		with open(self.inputFile.get(), "rb") as f:
			plainContent = f.read()
		random_hex_str = func.random_hex(crypt_sm2.para_len)
		signature = crypt_sm2.sign(plainContent, random_hex_str)

		del(priKey)
		del(plainContent)
		del(random_hex_str)
		signFile = "%s.sig"%self.inputFile.get()
		with open(signFile, "wt") as f:
			f.write(signature)
		del(signature)
		messagebox.showinfo(u"签名结束", u"已写入%s"%signFile)

	def sm2Verify(self):
		from gmssl.sm2 import CryptSM2
		pubKeyFile = filedialog.askopenfilename(initialdir = ".", title = u"选择公钥", filetypes = [("Public key", ("*.pub")), ("All files", "*.*")])
		if pubKeyFile == '':
			return
		with open(pubKeyFile, 'rt') as f:
			pubKey = f.read()
		if len(pubKey) < 64:
			messagebox.showerror(u"错误", u"公钥不正确！")
			del(pubKey)
			return

		signFile = filedialog.askopenfilename(initialdir = ".", title = u"选择签名", filetypes = [("Signature file", ("*.sig")), ("All files", "*.*")])
		with open(signFile, 'rt') as f:
			signature = f.read()
		if not len(signature) == 128:
			messagebox.showerror(u"错误", u"公钥不正确！")
			del(pubKey)
			del(signature)
			return

		crypt_sm2 = CryptSM2(public_key = pubKey, private_key = None)
		with open(self.inputFile.get(), "rb") as f:
			plainContent = f.read()
		if crypt_sm2.verify(signature, plainContent):
			messagebox.showinfo(u"验证结束", u"签名正确！")
		else:
			messagebox.showwarning(u"验证结束", u"签名不正确！")

		del(pubKey)
		del(plainContent)
		del(signature)

	def sm2Encrypt(self):
		from gmssl.sm2 import CryptSM2

		pubKeyFile = filedialog.askopenfilename(initialdir = ".", title = u"选择公钥", filetypes = [("Public key", ("*.pub")), ("All files", "*.*")])
		if pubKeyFile == '':
			return
		with open(pubKeyFile, 'rt') as f:
			pubKey = f.read()
		if len(pubKey) < 128:
			messagebox.showerror(u"错误", u"公钥不正确！")
			del(pubKey)
			return

		crypt_sm2 = CryptSM2(public_key = pubKey, private_key = None)
		with open(self.inputFile.get(), "rb") as f:
			plainContent = f.read()
		cipherContent = crypt_sm2.encrypt(plainContent)

		del(pubKey)
		del(plainContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(cipherContent)
		del(cipherContent)
		messagebox.showinfo(u"加密结束", u"已写入%s"%self.outputFile.get())

	def sm2Decrypt(self):
		from gmssl.sm2 import CryptSM2

		priKeyFile = filedialog.askopenfilename(initialdir = ".", title = u"选择私钥", filetypes = [("Private key", ("*.pri")), ("All files", "*.*")])
		if priKeyFile == '':
			return
		with open(priKeyFile, 'rt') as f:
			priKey = f.read()
		if len(priKey) < 64:
			messagebox.showerror(u"错误", u"私钥不正确！")
			del(priKey)
			return

		crypt_sm2 = CryptSM2(public_key = None, private_key = priKey)
		with open(self.inputFile.get(), "rb") as f:
			cipherContent = f.read()
		plainContent = crypt_sm2.decrypt(cipherContent)

		del(priKey)
		del(cipherContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(plainContent)
		del(plainContent)
		messagebox.showinfo(u"解密结束", u"已写入%s"%self.outputFile.get())

	def sm4Encrypt(self):
		from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

		self.root.attributes("-disabled", 1) #密码输入
		inputKeyWindow = acquireKey(self.root)
		self.root.attributes("-disabled", 0)

		try:
			key = bytes(self.sm3Hash(inputStr = inputKeyWindow.key, lengthInBits = 128), "UTF-8") #SM4需要128bits的密钥，这里取输入密码SM3哈希的前128bits
		except:
			return
		with open(self.inputFile.get(), "rb") as f:
			plainContent = f.read()
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_ENCRYPT)
		cipherContent = crypt_sm4.crypt_ecb(plainContent)

		del(key)
		del(plainContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(cipherContent)
		del(cipherContent)
		messagebox.showinfo(u"加密结束", u"已写入%s"%self.outputFile.get())

	def sm4Decrypt(self):
		from gmssl.sm4 import CryptSM4, SM4_DECRYPT

		self.root.attributes("-disabled", 1)
		inputKeyWindow = acquireKey(self.root)
		self.root.attributes("-disabled", 0)

		try:
			key = bytes(self.sm3Hash(inputStr = inputKeyWindow.key, lengthInBits = 128), "UTF-8") #SM4需要128bits的密钥，这里取输入密码SM3哈希的前128bits
		except:
			return
		with open(self.inputFile.get(), "rb") as f:
			cipherContent = f.read()
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_DECRYPT)
		plainContent = crypt_sm4.crypt_ecb(cipherContent)

		del(key)
		del(cipherContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(plainContent)
		del(plainContent)
		messagebox.showinfo(u"解密结束", u"已写入%s"%self.outputFile.get())

	def sm3Hash(self, inputStr = None, inputRaw = None, lengthInBits = 256):
		from gmssl.sm3 import sm3_hash

		if not (inputStr or inputRaw):
			return
		if lengthInBits < 0 or lengthInBits > 256: #范围控制
			return
		lengthInBytes = round(lengthInBits / 8)
		if inputStr:
			return sm3_hash(list(bytes(inputStr, "UTF-8")))[:lengthInBytes]
		else:
			return sm3_hash(list(inputRaw))[:lengthInBytes]

if __name__ == "__main__":
	GUI()